/*************************************************************************
 *
 * Copyright 2016 Realm Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************/

#include <realm/util/encrypted_file_mapping.hpp>

#include <realm/util/backtrace.hpp>
#include <realm/util/file_mapper.hpp>

#include <sstream>

#if REALM_ENABLE_ENCRYPTION
#include <realm/util/aes_cryptor.hpp>
#include <realm/util/errno.hpp>
#include <realm/util/sha_crypto.hpp>
#include <realm/util/terminate.hpp>
#include <realm/utilities.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <thread>

#ifdef REALM_DEBUG
#include <cstdio>
#endif

#if defined(_WIN32)
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace realm::util {
// We have the following constraints here:
//
// 1. When writing, we only know which 4k page is dirty, and not what bytes
//    within the page are dirty, so we always have to write in 4k blocks.
// 2. Pages being written need to be entirely within an 8k-aligned block to
//    ensure that they're written to the hardware in atomic blocks.
// 3. We need to store the IV used for each 4k page somewhere, so that we can
//    ensure that we never reuse an IV (and still be decryptable).
//
// Because pages need to be aligned, we can't just prepend the IV to each page,
// or we'd have to double the size of the file (as the rest of the 4k block
// containing the IV would not be usable). Writing the IVs to a different part
// of the file from the data results in them not being in the same 8k block, and
// so it is possible that only the IV or only the data actually gets updated on
// disk. We deal with this by storing four pieces of data about each page: the
// hash of the encrypted data, the current IV, the hash of the previous encrypted
// data, and the previous IV. To write, we encrypt the data, hash the ciphertext,
// then write the new IV/ciphertext hash, fsync(), and then write the new
// ciphertext. This ensures that if an error occurs between writing the IV and
// the ciphertext, we can still determine that we should use the old IV, since
// the ciphertext's hash will match the old ciphertext.

// This produces a file on disk with the following layout:
// 4k block of metadata   (up to 64 IVTable instances stored here)
// 64 * 4k blocks of data (up to 262144 bytes of data are stored here)
// 4k block of metadata
// 64 * 4k blocks of data
// ...

struct IVTable {
    uint32_t iv1 = 0;
    std::array<uint8_t, 28> hmac1 = {};
    uint32_t iv2 = 0;
    std::array<uint8_t, 28> hmac2 = {};
    bool operator==(const IVTable& other) const
    {
        return iv1 == other.iv1 && iv2 == other.iv2 && hmac1 == other.hmac1 && hmac2 == other.hmac2;
    }
    bool operator!=(const IVTable& other) const
    {
        return !(*this == other);
    }
};
// We read this via memcpy and need it to be packed
static_assert(sizeof(IVTable) == 64);

namespace {
constexpr uint8_t aes_block_size = 16;
constexpr uint16_t block_size = 4096;
constexpr uint8_t block_shift = 12; // std::bit_width(block_size)

constexpr uint8_t metadata_size = sizeof(IVTable);
constexpr uint8_t blocks_per_metadata_block = block_size / metadata_size;
static_assert(metadata_size == 64,
              "changing the size of the metadata breaks compatibility with existing Realm files");

using SizeType = File::SizeType;

// map an offset in the data to the actual location in the file
SizeType real_offset(SizeType pos)
{
    REALM_ASSERT(pos >= 0);
    const SizeType index = pos / block_size;
    const SizeType metadata_page_count = index / blocks_per_metadata_block + 1;
    return pos + metadata_page_count * block_size;
}

// map a location in the file to the offset in the data
SizeType fake_offset(SizeType pos)
{
    REALM_ASSERT(pos >= 0);
    const SizeType index = pos / block_size;
    const SizeType metadata_page_count = (index + blocks_per_metadata_block) / (blocks_per_metadata_block + 1);
    return pos - metadata_page_count * block_size;
}

// get the location of the IVTable for the given data (not file) position
SizeType iv_table_pos(SizeType pos)
{
    REALM_ASSERT(pos >= 0);
    const SizeType index = pos / block_size;
    const SizeType metadata_block = index / blocks_per_metadata_block;
    const SizeType metadata_index = index & (blocks_per_metadata_block - 1);
    return metadata_block * (blocks_per_metadata_block + 1) * block_size + metadata_index * metadata_size;
}

size_t check_read(FileDesc fd, SizeType pos, void* dst, size_t len)
{
    return File::read_static(fd, pos, static_cast<char*>(dst), len);
}

// first block is iv data, second page is data
static_assert(c_min_encrypted_file_size == 2 * block_size,
              "chaging the block size breaks encrypted file portability");

template <class T, size_t N, std::size_t... I>
constexpr std::array<T, N> to_array_impl(const T* ptr, std::index_sequence<I...>)
{
    return {{ptr[I]...}};
}
template <class T, size_t N>
constexpr auto to_array(const T* ptr)
{
    return to_array_impl<T, N>(ptr, std::make_index_sequence<N>{});
}

} // anonymous namespace

AESCryptor::AESCryptor(const char* key)
    : m_key(to_array<uint8_t, 64>(reinterpret_cast<const uint8_t*>(key)))
    , m_rw_buffer(new char[block_size])
    , m_dst_buffer(new char[block_size])
{
#if REALM_PLATFORM_APPLE
    // A random iv is passed to CCCryptorReset. This iv is *not used* by Realm; we set it manually prior to
    // each call to BCryptEncrypt() and BCryptDecrypt(). We pass this random iv as an attempt to
    // suppress a false encryption security warning from the IBM Bluemix Security Analyzer (PR[#2911])
    unsigned char u_iv[kCCKeySizeAES256];
    arc4random_buf(u_iv, kCCKeySizeAES256);
    void* iv = u_iv;
    CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, 0 /* options */, key, kCCKeySizeAES256, iv, &m_encr);
    CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, 0 /* options */, key, kCCKeySizeAES256, iv, &m_decr);
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    int ret;
    ret = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    REALM_ASSERT_RELEASE_EX(ret == 0 && "BCryptOpenAlgorithmProvider()", ret);

    ret = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                            sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    REALM_ASSERT_RELEASE_EX(ret == 0 && "BCryptSetProperty()", ret);

    ret = BCryptGenerateSymmetricKey(hAesAlg, &m_aes_key_handle, nullptr, 0, (PBYTE)key, 32, 0);
    REALM_ASSERT_RELEASE_EX(ret == 0 && "BCryptGenerateSymmetricKey()", ret);
#else
    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx)
        handle_error();
#endif
}

AESCryptor::~AESCryptor() noexcept
{
#if REALM_PLATFORM_APPLE
    CCCryptorRelease(m_encr);
    CCCryptorRelease(m_decr);
#elif defined(_WIN32)
#else
    EVP_CIPHER_CTX_cleanup(m_ctx);
    EVP_CIPHER_CTX_free(m_ctx);
#endif
}

void AESCryptor::handle_error()
{
    throw std::runtime_error("Error occurred in encryption layer");
}

template <typename To, typename From>
To checked_cast(From from)
{
    To to;
    if (REALM_UNLIKELY(int_cast_with_overflow_detect(from, to))) {
        throw MaximumFileSizeExceeded(util::format("File size %1 is larger than can be represented", from));
    }
    return to;
}

void AESCryptor::set_file_size(SizeType new_size)
{
    REALM_ASSERT(new_size >= 0);
    SizeType block_count = (new_size + block_size - 1) / block_size;
    m_iv_buffer.reserve(round_up(checked_cast<size_t>(block_count), blocks_per_metadata_block));
    m_iv_buffer_cache.reserve(m_iv_buffer.capacity());
}

IVTable& AESCryptor::get_iv_table(FileDesc fd, SizeType data_pos, IVLookupMode mode) noexcept
{
    REALM_ASSERT(!int_cast_has_overflow<size_t>(data_pos));
    size_t data_pos_casted = size_t(data_pos);
    size_t idx = data_pos_casted / block_size;
    if (mode == IVLookupMode::UseCache && idx < m_iv_buffer.size())
        return m_iv_buffer[idx];

    size_t block_start = std::min(m_iv_buffer.size(), round_down(idx, blocks_per_metadata_block));
    size_t block_end = 1 + idx / blocks_per_metadata_block;
    REALM_ASSERT(block_end * blocks_per_metadata_block <= m_iv_buffer.capacity()); // not safe to allocate here
    if (block_end * blocks_per_metadata_block > m_iv_buffer.size()) {
        m_iv_buffer.resize(block_end * blocks_per_metadata_block);
        m_iv_buffer_cache.resize(m_iv_buffer.size());
    }

    for (size_t i = block_start; i < block_end * blocks_per_metadata_block; i += blocks_per_metadata_block) {
        SizeType iv_pos = iv_table_pos(SizeType(i) * block_size);
        size_t bytes = check_read(fd, iv_pos, &m_iv_buffer[i], block_size);
        if (bytes < block_size)
            break; // rest is zero-filled by resize()
    }

    return m_iv_buffer[idx];
}

bool AESCryptor::check_hmac(const void* src, size_t len, const std::array<uint8_t, 28>& hmac) const
{
    std::array<uint8_t, 224 / 8> buffer;
    hmac_sha224(Span(reinterpret_cast<const uint8_t*>(src), len), buffer, Span(m_key).sub_span<32>());

    // Constant-time memcmp to avoid timing attacks
    uint8_t result = 0;
    for (size_t i = 0; i < 224 / 8; ++i)
        result |= buffer[i] ^ hmac[i];
    return result == 0;
}

std::vector<IVRefreshState> AESCryptor::refresh_ivs(FileDesc fd, size_t begin, size_t end)
{
    REALM_ASSERT(begin < end);

    const size_t first_block_ndx = round_down(begin, blocks_per_metadata_block);
    get_iv_table(fd, SizeType(first_block_ndx) * block_size, IVLookupMode::Refetch);
    const size_t block_count = std::min(end, first_block_ndx + blocks_per_metadata_block) - begin;

    constexpr IVTable uninitialized_iv = {};
    std::vector<IVRefreshState> block_states;
    block_states.resize(block_count, IVRefreshState::UpToDate);
    // FIXME: this discards some of the information we just read. This is
    // probably less efficient than it could be as a result
    for (size_t i = 0; i < block_count; ++i) {
        size_t block = begin + i;
        if (m_iv_buffer_cache[block] != m_iv_buffer[block] || m_iv_buffer[block] == uninitialized_iv) {
            block_states[i] = IVRefreshState::RequiresRefresh;
            m_iv_buffer_cache[block] = m_iv_buffer[block];
        }
    }
    return block_states;
}

size_t AESCryptor::read(FileDesc fd, SizeType pos, char* dst, size_t size, WriteObserver* observer)
{
    REALM_ASSERT_EX(size % block_size == 0, size, block_size);
    // We need to throw DecryptionFailed if the key is incorrect or there has been a corruption in the data but
    // not in a reader starvation scenario where a different process is writing pages and ivs faster than we can read
    // them. We also want to optimize for a single process writer since in that case all the cached ivs are correct.
    // To do this, we first attempt to use the cached IV, and if it is invalid, read from disk again. During reader
    // starvation, the just read IV could already be out of date with the data page, so continue trying to read until
    // a match is found (for up to 5 seconds before giving up entirely).
    size_t retry_count = 0;
    std::pair<IVTable, size_t> last_iv_and_data_hash;
    auto retry_start_time = std::chrono::steady_clock::now();
    size_t num_identical_reads = 1;
    auto retry = [&](std::string_view page_data, const IVTable& iv, const char* debug_from) {
        constexpr auto max_retry_period = std::chrono::seconds(5);
        auto elapsed = std::chrono::steady_clock::now() - retry_start_time;
        // not having an observer set means that we're alone. (or should mean it)
        bool we_are_alone = !observer || observer->no_concurrent_writer_seen();
        if (we_are_alone || (retry_count > 0 && elapsed > max_retry_period)) {
            auto str = util::format("unable to decrypt after %1 seconds (retry_count=%2, from=%3, size=%4)",
                                    std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), retry_count,
                                    debug_from, size);
            // std::cerr << std::endl << "*Timeout: " << str << std::endl;
            throw DecryptionFailed(str);
        }

        // don't wait on the first retry as we want to optimize the case where the first read
        // from the iv table cache didn't validate and we are fetching the iv block from disk for the first time
        auto cur_iv_and_data_hash = std::make_pair(iv, std::hash<std::string_view>{}(page_data));
        if (retry_count != 0) {
            if (last_iv_and_data_hash == cur_iv_and_data_hash) {
                ++num_identical_reads;
            }
            // don't retry right away if there are potentially other external writers
            std::this_thread::yield();
        }
        last_iv_and_data_hash = cur_iv_and_data_hash;
        ++retry_count;
    };

    auto should_retry = [&]() -> bool {
        // if we don't have an observer object or it hasn't seen any other writers,
        // we're guaranteed to be alone in the world and retrying will not help us,
        // since the file is not being changed.
        if (!observer || observer->no_concurrent_writer_seen())
            return false;
        // if we do not observe identical data or iv within several sequential reads then
        // this is a multiprocess reader starvation scenario so keep trying until we get a match
        return retry_count <= 5 || (retry_count - num_identical_reads > 1 && retry_count < 20);
    };

    size_t bytes_read = 0;
    while (bytes_read < size) {
        size_t actual = check_read(fd, real_offset(pos), m_rw_buffer.get(), block_size);

        if (actual == 0)
            return bytes_read;

        IVTable& iv = get_iv_table(fd, pos, retry_count == 0 ? IVLookupMode::UseCache : IVLookupMode::Refetch);
        if (iv.iv1 == 0) {
            if (should_retry()) {
                retry(std::string_view{m_rw_buffer.get(), block_size}, iv, "iv1 == 0");
                continue;
            }
            // This block has never been written to, so we've just read pre-allocated
            // space. No memset() since the code using this doesn't rely on
            // pre-allocated space being zeroed.
            return bytes_read;
        }

        if (!check_hmac(m_rw_buffer.get(), actual, iv.hmac1)) {
            // Either the DB is corrupted or we were interrupted between writing the
            // new IV and writing the data
            if (iv.iv2 == 0) {
                if (should_retry()) {
                    retry(std::string_view{m_rw_buffer.get(), block_size}, iv, "iv2 == 0");
                    continue;
                }
                // Very first write was interrupted
                return bytes_read;
            }

            if (check_hmac(m_rw_buffer.get(), actual, iv.hmac2)) {
                // Un-bump the IV since the write with the bumped IV never actually
                // happened
                memcpy(&iv.iv1, &iv.iv2, 32);
            }
            else {
                // If the file has been shrunk and then re-expanded, we may have
                // old hmacs that don't go with this data. ftruncate() is
                // required to fill any added space with zeroes, so assume that's
                // what happened if the buffer is all zeroes
                size_t i;
                for (i = 0; i < actual; ++i) {
                    if (m_rw_buffer[i] != 0) {
                        break;
                    }
                }
                if (i != actual) {
                    // at least one byte wasn't zero
                    retry(std::string_view{m_rw_buffer.get(), block_size}, iv, "i != bytes_read");
                    continue;
                }
                return bytes_read;
            }
        }

        // We may expect some adress ranges of the destination buffer of
        // AESCryptor::read() to stay unmodified, i.e. being overwritten with
        // the same bytes as already present, and may have read-access to these
        // from other threads while decryption is taking place.
        //
        // However, some implementations of AES_cbc_encrypt(), in particular
        // OpenSSL, will put garbled bytes as an intermediate step during the
        // operation which will lead to incorrect data being read by other
        // readers concurrently accessing that page. Incorrect data leads to
        // crashes.
        //
        // We therefore decrypt to a temporary buffer first and then copy the
        // completely decrypted data after.
        crypt(mode_Decrypt, pos, m_dst_buffer.get(), m_rw_buffer.get(), reinterpret_cast<const char*>(&iv.iv1));
        memcpy(dst, m_dst_buffer.get(), block_size);

        pos += block_size;
        dst += block_size;
        bytes_read += block_size;
        retry_count = 0;
    }
    return bytes_read;
}

void AESCryptor::try_read_block(FileDesc fd, SizeType pos, char* dst) noexcept
{
    size_t bytes_read = check_read(fd, real_offset(pos), m_rw_buffer.get(), block_size);

    if (bytes_read == 0) {
        std::cerr << "Read failed: 0x" << std::hex << pos << std::endl;
        memset(dst, 0x55, block_size);
        return;
    }

    IVTable& iv = get_iv_table(fd, pos, IVLookupMode::Refetch);
    if (iv.iv1 == 0) {
        std::cerr << "Block never written: 0x" << std::hex << pos << std::endl;
        memset(dst, 0xAA, block_size);
        return;
    }

    if (!check_hmac(m_rw_buffer.get(), bytes_read, iv.hmac1)) {
        if (iv.iv2 == 0) {
            std::cerr << "First write interrupted: 0x" << std::hex << pos << std::endl;
        }

        if (check_hmac(m_rw_buffer.get(), bytes_read, iv.hmac2)) {
            std::cerr << "Restore old IV: 0x" << std::hex << pos << std::endl;
            memcpy(&iv.iv1, &iv.iv2, 32);
        }
        else {
            std::cerr << "Checksum failed: 0x" << std::hex << pos << std::endl;
        }
    }
    crypt(mode_Decrypt, pos, dst, m_rw_buffer.get(), reinterpret_cast<const char*>(&iv.iv1));
}

void AESCryptor::write(FileDesc fd, SizeType pos, const char* src, size_t size, WriteMarker* marker) noexcept
{
    REALM_ASSERT(size % block_size == 0);
    while (size > 0) {
        IVTable& iv = get_iv_table(fd, pos);

        memcpy(&iv.iv2, &iv.iv1, 32); // this is also copying the hmac
        do {
            ++iv.iv1;
            // 0 is reserved for never-been-used, so bump if we just wrapped around
            if (iv.iv1 == 0)
                ++iv.iv1;

            crypt(mode_Encrypt, pos, m_rw_buffer.get(), src, reinterpret_cast<const char*>(&iv.iv1));
            hmac_sha224(Span(reinterpret_cast<uint8_t*>(m_rw_buffer.get()), block_size), iv.hmac1,
                        Span(m_key).sub_span<32>());
            // In the extremely unlikely case that both the old and new versions have
            // the same hash we won't know which IV to use, so bump the IV until
            // they're different.
        } while (REALM_UNLIKELY(iv.hmac1 == iv.hmac2));

        if (marker)
            marker->mark(pos);
        File::write_static(fd, iv_table_pos(pos), reinterpret_cast<const char*>(&iv), sizeof(iv));
        File::write_static(fd, real_offset(pos), m_rw_buffer.get(), block_size);
        if (marker)
            marker->unmark();

        pos += block_size;
        src += block_size;
        size -= block_size;
    }
}

void AESCryptor::crypt(EncryptionMode mode, SizeType pos, char* dst, const char* src, const char* stored_iv) noexcept
{
    uint8_t iv[aes_block_size] = {0};
    memcpy(iv, stored_iv, 4);
    memcpy(iv + 4, &pos, sizeof(pos));

#if REALM_PLATFORM_APPLE
    CCCryptorRef cryptor = mode == mode_Encrypt ? m_encr : m_decr;
    CCCryptorReset(cryptor, iv);

    size_t bytesEncrypted = 0;
    CCCryptorStatus err = CCCryptorUpdate(cryptor, src, block_size, dst, block_size, &bytesEncrypted);
    REALM_ASSERT(err == kCCSuccess);
    REALM_ASSERT(bytesEncrypted == block_size);
#elif defined(_WIN32)
    ULONG cbData;
    int i;

    if (mode == mode_Encrypt) {
        i = BCryptEncrypt(m_aes_key_handle, (PUCHAR)src, block_size, nullptr, (PUCHAR)iv, sizeof(iv), (PUCHAR)dst,
                          block_size, &cbData, 0);
        REALM_ASSERT_RELEASE_EX(i == 0 && "BCryptEncrypt()", i);
        REALM_ASSERT_RELEASE_EX(cbData == block_size && "BCryptEncrypt()", cbData);
    }
    else if (mode == mode_Decrypt) {
        i = BCryptDecrypt(m_aes_key_handle, (PUCHAR)src, block_size, nullptr, (PUCHAR)iv, sizeof(iv), (PUCHAR)dst,
                          block_size, &cbData, 0);
        REALM_ASSERT_RELEASE_EX(i == 0 && "BCryptDecrypt()", i);
        REALM_ASSERT_RELEASE_EX(cbData == block_size && "BCryptDecrypt()", cbData);
    }
    else {
        REALM_UNREACHABLE();
    }

#else
    if (!EVP_CipherInit_ex(m_ctx, EVP_aes_256_cbc(), NULL, m_key.data(), iv, mode))
        handle_error();

    int len;
    // Use zero padding - we always write a whole page
    EVP_CIPHER_CTX_set_padding(m_ctx, 0);

    if (!EVP_CipherUpdate(m_ctx, reinterpret_cast<uint8_t*>(dst), &len, reinterpret_cast<const uint8_t*>(src),
                          block_size))
        handle_error();

    // Finalize the encryption. Should not output further data.
    if (!EVP_CipherFinal_ex(m_ctx, reinterpret_cast<uint8_t*>(dst) + len, &len))
        handle_error();
#endif
}

std::unique_ptr<EncryptedFileMapping> EncryptedFile::add_mapping(SizeType file_offset, void* addr, size_t size,
                                                                 File::AccessMode access)
{
    auto mapping = std::make_unique<EncryptedFileMapping>(*this, file_offset, addr, size, access);
    CheckedLockGuard lock(mutex);
    mappings.push_back(mapping.get());
    return mapping;
}

EncryptedFileMapping::EncryptedFileMapping(EncryptedFile& file, SizeType file_offset, void* addr, size_t size,
                                           File::AccessMode access, util::WriteObserver* observer,
                                           util::WriteMarker* marker)
    : m_file(file)
    , m_access(access)
    , m_observer(observer)
    , m_marker(marker)
#ifdef REALM_DEBUG
    , m_validate_buffer(new char[block_size])
#endif
{
    set(addr, size, file_offset); // throws
}

EncryptedFileMapping::~EncryptedFileMapping()
{
    CheckedLockGuard lock(m_file.mutex);
    for (auto& e : m_block_state) {
        REALM_ASSERT(is_not(e, Writable));
    }
    if (m_access == File::access_ReadWrite) {
        do_sync();
    }

    // FIXME: might be worth intrusive listing this?
    auto it = std::find(m_file.mappings.begin(), m_file.mappings.end(), this);
    REALM_ASSERT(it != m_file.mappings.end());
    if (it != m_file.mappings.end()) {
        m_file.mappings.erase(it);
    }
}

// offset within block, not within file
uint16_t EncryptedFileMapping::get_offset_of_address(const void* addr) const noexcept
{
    return reinterpret_cast<uintptr_t>(addr) & (block_size - 1);
}

size_t EncryptedFileMapping::get_local_index_of_address(const void* addr, size_t offset) const noexcept
{
    REALM_ASSERT_EX(addr >= m_addr, addr, m_addr);
    return (reinterpret_cast<uintptr_t>(addr) - reinterpret_cast<uintptr_t>(m_addr) + offset) >> block_shift;
}

bool EncryptedFileMapping::contains_block(size_t block_in_file) const noexcept
{
    return block_in_file - m_first_block < m_block_state.size();
}

char* EncryptedFileMapping::block_addr(size_t local_ndx) const noexcept
{
    REALM_ASSERT_DEBUG(local_ndx < m_block_state.size());
    return static_cast<char*>(m_addr) + (local_ndx << block_shift);
}

SizeType EncryptedFileMapping::block_pos(size_t local_ndx) const noexcept
{
    return SizeType(local_ndx + m_first_block) << block_shift;
}

void EncryptedFileMapping::mark_outdated(size_t local_ndx) noexcept
{
    if (local_ndx >= m_block_state.size())
        return;
    REALM_ASSERT(is_not(m_block_state[local_ndx], UpToDate));
    REALM_ASSERT(is_not(m_block_state[local_ndx], Dirty));
    REALM_ASSERT(is_not(m_block_state[local_ndx], Writable));
}

// If we have multiple mappings for the same part of the file, one of them may
// already contain the page we're about to read and if so we can skip reading
// it and instead just memcpy it.
bool EncryptedFileMapping::copy_up_to_date_block(size_t local_ndx) noexcept
{
    REALM_ASSERT_EX(local_ndx < m_block_state.size(), local_ndx, m_block_state.size());
    // Precondition: this method must never be called for a page which
    // is already up to date.
    REALM_ASSERT(is_not(m_block_state[local_ndx], UpToDate));
    size_t ndx_in_file = local_ndx + m_first_block;
    for (auto& m : m_file.mappings) {
        m->assert_locked();
        if (m == this || !m->contains_block(ndx_in_file))
            continue;

        size_t other_mapping_ndx = ndx_in_file - m->m_first_block;
        if (is_not(m->m_block_state[other_mapping_ndx], UpToDate))
            continue;

        memcpy(block_addr(local_ndx), m->block_addr(other_mapping_ndx), block_size);
        set(m_block_state[local_ndx], UpToDate);
        clear(m_block_state[local_ndx], StaleIV);
        return true;
    }
    return false;
}

// Whenever we advance our reader view of the file we mark all previously
// up-to-date pages as being possibly stale. On the next access of the page we
// then check if the IV for that page has changed to determine if the page has
// actually changed or if we can just mark it as being up-to-date again.
bool EncryptedFileMapping::check_possibly_stale_block(size_t local_ndx) noexcept
{
    if (is_not(m_block_state[local_ndx], StaleIV))
        return false;

    // Reread the IV block which contains this page. This will check the validity
    // of up to 64 pages as we can read them all in one shot.
    const size_t ndx_in_file = local_ndx + m_first_block;
    auto refreshed_ivs = m_file.cryptor.refresh_ivs(m_file.fd, ndx_in_file, m_first_block + m_block_state.size());
    REALM_ASSERT(!refreshed_ivs.empty());

    for (size_t i = 0; i < refreshed_ivs.size(); ++i) {
        size_t local_ndx_of_iv_change = i + local_ndx;
        // FIXME: explain why this is correct
        REALM_ASSERT_RELEASE_EX(!is(m_block_state[local_ndx_of_iv_change], Dirty | Writable),
                                m_block_state[local_ndx_of_iv_change]);
        switch (refreshed_ivs[i]) {
            case IVRefreshState::UpToDate:
                // IV didn't change, so if it was possibly up to date then
                // it actually is
                if (is(m_block_state[local_ndx_of_iv_change], StaleIV)) {
                    set(m_block_state[local_ndx_of_iv_change], UpToDate);
                    clear(m_block_state[local_ndx_of_iv_change], StaleIV);
                }
                break;
                // IV did change, so regardless of the previous state it was
                // in it needs to be refreshed
            case IVRefreshState::RequiresRefresh:
                clear(m_block_state[local_ndx_of_iv_change], StaleIV);
                clear(m_block_state[local_ndx_of_iv_change], UpToDate);
                break;
        }
    }

    // Report whether the specific page we actually care about actually changed
    return refreshed_ivs[0] == IVRefreshState::UpToDate;
}

void EncryptedFileMapping::refresh_block(size_t local_ndx, bool to_modify)
{
    REALM_ASSERT_EX(local_ndx < m_block_state.size(), local_ndx, m_block_state.size());
    REALM_ASSERT(is_not(m_block_state[local_ndx], Dirty));
    REALM_ASSERT(is_not(m_block_state[local_ndx], Writable));
    if (copy_up_to_date_block(local_ndx) || check_possibly_stale_block(local_ndx)) {
        return;
    }

    char* addr = block_addr(local_ndx);
    size_t actual = m_file.cryptor.read(m_file.fd, block_pos(local_ndx), addr, block_size, m_observer);
    if (actual != block_size && !to_modify) {
        size_t fs = to_size_t(File::get_size_static(m_file.fd));
        throw DecryptionFailed(
            util::format("failed to decrypt block %1 in file of size %2", local_ndx + m_first_block, fs));
    }
    set(m_block_state[local_ndx], UpToDate);
    clear(m_block_state[local_ndx], StaleIV);
}

void EncryptedFileMapping::mark_pages_for_iv_check()
{
    util::CheckedLockGuard lock(m_file.mutex);
    for (auto& m : m_file.mappings) {
        m->assert_locked();
        for (auto& state : m->m_block_state) {
            if (is(state, UpToDate) && is_not(state, Dirty | Writable)) {
                REALM_ASSERT(is_not(state, StaleIV));
                clear(state, UpToDate);
                set(state, StaleIV);
            }
        }
    }
}

void EncryptedFileMapping::write_and_update_all(size_t local_ndx, uint16_t offset, uint16_t size) noexcept
{
    REALM_ASSERT(is(m_block_state[local_ndx], Writable));
    REALM_ASSERT(is(m_block_state[local_ndx], UpToDate));
    REALM_ASSERT(is_not(m_block_state[local_ndx], StaleIV));
    // Go through all other mappings of this file and copy changes into those mappings
    size_t ndx_in_file = local_ndx + m_first_block;
    for (auto& m : m_file.mappings) {
        m->assert_locked();
        if (m == this || !m->contains_block(ndx_in_file))
            continue;

        size_t other_local_ndx = ndx_in_file - m->m_first_block;
        auto& state = m->m_block_state[other_local_ndx];
        if (is(state, UpToDate) || is(state, StaleIV)) { // only keep up to data pages up to date
            memcpy(m->block_addr(other_local_ndx) + offset, block_addr(local_ndx) + offset, size);
            set(state, UpToDate);
            clear(state, StaleIV);
        }
    }
    set(m_block_state[local_ndx], Dirty);
    clear(m_block_state[local_ndx], Writable);
    //    clear(m_block_state[local_ndx], StaleIV);
}


void EncryptedFileMapping::validate_block(size_t local_ndx) noexcept
{
#ifdef REALM_DEBUG
    REALM_ASSERT(local_ndx < m_block_state.size());
    if (is_not(m_block_state[local_ndx], UpToDate))
        return;

    if (!m_file.cryptor.read(m_file.fd, block_pos(local_ndx), m_validate_buffer.get(), block_size, m_observer))
        return;

    const size_t ndx_in_file = local_ndx + m_first_block;
    for (auto& m : m_file.mappings) {
        m->assert_locked();
        size_t other_local_ndx = ndx_in_file - m->m_first_block;
        if (m != this && m->contains_block(ndx_in_file) && is(m->m_block_state[other_local_ndx], Dirty)) {
            memcpy(m_validate_buffer.get(), m->block_addr(other_local_ndx), block_size);
            break;
        }
    }

    if (memcmp(m_validate_buffer.get(), block_addr(local_ndx), block_size) != 0) {
        util::format(std::cerr, "mismatch %1: fd(%2) block(%3/%4) %5 %6\n", this, m_file.fd, local_ndx,
                     m_block_state.size(), m_validate_buffer.get(), block_addr(local_ndx));
        REALM_TERMINATE("");
    }
#else
    static_cast<void>(local_ndx);
#endif
}

void EncryptedFileMapping::validate() noexcept
{
#ifdef REALM_DEBUG
    for (size_t i = 0; i < m_block_state.size(); ++i)
        validate_block(i);
#endif
}

void EncryptedFileMapping::do_flush() noexcept
{
    for (size_t i = 0; i < m_block_state.size(); ++i) {
        if (is_not(m_block_state[i], Dirty)) {
            validate_block(i);
            continue;
        }
        m_file.cryptor.write(m_file.fd, block_pos(i), block_addr(i), block_size, m_marker);
        clear(m_block_state[i], Dirty);
    }

    validate();
}

void EncryptedFileMapping::flush() noexcept
{
    util::CheckedLockGuard lock(m_file.mutex);
    do_flush();
}

void EncryptedFileMapping::sync() noexcept
{
    util::CheckedLockGuard lock(m_file.mutex);
    do_sync();
}

#ifdef _MSC_VER
#pragma warning(disable : 4297) // throw in noexcept
#endif
void EncryptedFileMapping::do_sync() noexcept
{
    do_flush();

#ifdef _WIN32
    if (FlushFileBuffers(m_file.fd))
        return;
    throw std::system_error(GetLastError(), std::system_category(), "FlushFileBuffers() failed");
#else
    fsync(m_file.fd);
#endif
}
#ifdef _MSC_VER
#pragma warning(default : 4297)
#endif

void EncryptedFileMapping::write_barrier(const void* addr, size_t size) noexcept
{
    CheckedLockGuard lock(m_file.mutex);
    REALM_ASSERT(size > 0);
    REALM_ASSERT(m_access == File::access_ReadWrite);

    size_t local_block = get_local_index_of_address(addr);
    REALM_ASSERT(local_block < m_block_state.size());
    REALM_ASSERT(is(m_block_state[local_block], BlockState::Writable));
    size_t offset = static_cast<const char*>(addr) - block_addr(local_block);
    size += offset;

    // Propagate changes to all other decrypted pages mapping the same memory
    while (size > 0) {
        REALM_ASSERT(local_block < m_block_state.size());
        write_and_update_all(local_block, offset, std::min<size_t>(block_size, size - offset));
        offset = 0;
        size -= std::min<size_t>(size, block_size);
        ++local_block;
    }
}

void EncryptedFileMapping::read_barrier(const void* addr, size_t size, bool to_modify)
{
    CheckedLockGuard lock(m_file.mutex);
    REALM_ASSERT(size > 0);
    size_t begin = get_local_index_of_address(addr);
    size_t end = get_local_index_of_address(addr, size - 1);
    for (size_t local_block = begin; local_block <= end; ++local_block) {
        BlockState& ps = m_block_state[local_block];
        if (is_not(ps, UpToDate))
            refresh_block(local_block, to_modify);
        if (to_modify)
            set(ps, Writable);
    }
}

void EncryptedFileMapping::extend_to(SizeType offset, size_t new_size)
{
    CheckedLockGuard lock(m_file.mutex);
    REALM_ASSERT_EX(new_size % block_size == 0, new_size, block_size);
    size_t num_blocks = new_size / block_size;
    m_block_state.resize(num_blocks, BlockState::Clean);
    m_file.cryptor.set_file_size(offset + SizeType(new_size));
}

void EncryptedFileMapping::set(void* new_addr, size_t new_size, SizeType new_file_offset)
{
    CheckedLockGuard lock(m_file.mutex);
    REALM_ASSERT(new_file_offset % block_size == 0);
    REALM_ASSERT(new_size % block_size == 0);

    // This seems dangerous - correct operation in a setting with multiple (partial)
    // mappings of the same file would rely on ordering of individual mapping requests.
    // Currently we only ever extend the file - but when we implement continuous defrag,
    // this design should be revisited.
    m_file.cryptor.set_file_size(new_file_offset + SizeType(new_size));

    do_flush();
    m_addr = new_addr;

    m_first_block = new_file_offset / block_size;
    m_block_state.clear();
    m_block_state.resize(new_size >> block_shift, BlockState::Clean);
}

SizeType encrypted_size_to_data_size(SizeType size) noexcept
{
    return size == 0 ? 0 : fake_offset(size);
}

SizeType data_size_to_encrypted_size(SizeType size) noexcept
{
    return real_offset(round_up(size, block_size));
}
} // namespace realm::util
#else

namespace realm::util {
File::SizeType encrypted_size_to_data_size(File::SizeType size) noexcept
{
    return size;
}

File::SizeType data_size_to_encrypted_size(File::SizeType size) noexcept
{
    return size;
}
} // namespace realm::util
#endif // REALM_ENABLE_ENCRYPTION

namespace realm::util {
std::string DecryptionFailed::get_message_with_bt(std::string_view msg)
{
    auto bt = Backtrace::capture();
    std::stringstream ss;
    bt.print(ss);
    return util::format("Decryption failed: %1\n%2\n", msg, ss.str());
}
} // namespace realm::util

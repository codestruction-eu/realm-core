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

#include <realm/util/aes_cryptor.hpp>
#include <realm/util/file_mapper.hpp>
#include <realm/utilities.hpp>

#if REALM_ENABLE_ENCRYPTION
#include <cstdlib>
#include <algorithm>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <chrono>

#ifdef REALM_DEBUG
#include <cstdio>
#endif

#include <iostream>
#include <cstring>

#if defined(_WIN32)
#include <Windows.h>
// 224-bit AES-2 from https://github.com/kalven/sha-2 - Public Domain. Native API
// does not exist for 224 bits (only 128, 256, etc).
#include <win32/kalven-sha2/sha224.hpp>
#include <bcrypt.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include <realm/util/encrypted_file_mapping.hpp>
#include <realm/util/terminate.hpp>
#endif

namespace realm::util {

#if REALM_ENABLE_ENCRYPTION

SharedFileInfo::SharedFileInfo(const uint8_t* key)
    : cryptor(key)
{
}

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

struct iv_table {
    uint32_t iv1;
    uint8_t hmac1[28];
    uint32_t iv2;
    uint8_t hmac2[28];
    iv_table()
    {
        iv1 = 0;
        iv2 = 0;
        memset(&hmac1, 0, 28);
        memset(&hmac2, 0, 28);
    }
    iv_table(const iv_table& other)
    {
        iv1 = other.iv1;
        iv2 = other.iv2;
        memmove(&hmac1, &other.hmac1, 28);
        memmove(&hmac2, &other.hmac2, 28);
    }
    void operator=(const iv_table& other)
    {
        iv1 = other.iv1;
        iv2 = other.iv2;
        memmove(&hmac1, &other.hmac1, 28);
        memmove(&hmac2, &other.hmac2, 28);
    }
    bool operator==(const iv_table& other) const
    {
        return iv1 == other.iv1 && iv2 == other.iv2 && memcmp(hmac1, other.hmac1, 28) == 0 &&
               memcmp(hmac2, other.hmac2, 28) == 0;
    }
    bool operator!=(const iv_table& other) const
    {
        return !(*this == other);
    }
};

namespace {
const int aes_block_size = 16;
const size_t block_size = 4096;

const size_t metadata_size = sizeof(iv_table);
const size_t blocks_per_metadata_block = block_size / metadata_size;

// map an offset in the data to the actual location in the file
template <typename Int>
Int real_offset(Int pos)
{
    REALM_ASSERT(pos >= 0);
    const size_t index = static_cast<size_t>(pos) / block_size;
    const size_t metadata_page_count = index / blocks_per_metadata_block + 1;
    return Int(pos + metadata_page_count * block_size);
}

// map a location in the file to the offset in the data
template <typename Int>
Int fake_offset(Int pos)
{
    REALM_ASSERT(pos >= 0);
    const size_t index = static_cast<size_t>(pos) / block_size;
    const size_t metadata_page_count = (index + blocks_per_metadata_block) / (blocks_per_metadata_block + 1);
    return pos - metadata_page_count * block_size;
}

// get the location of the iv_table for the given data (not file) position
off_t iv_table_pos(off_t pos)
{
    REALM_ASSERT(pos >= 0);
    const size_t index = static_cast<size_t>(pos) / block_size;
    const size_t metadata_block = index / blocks_per_metadata_block;
    const size_t metadata_index = index & (blocks_per_metadata_block - 1);
    return off_t(metadata_block * (blocks_per_metadata_block + 1) * block_size + metadata_index * metadata_size);
}

void check_write(FileDesc fd, off_t pos, const void* data, size_t len)
{
    uint64_t orig = File::get_file_pos(fd);
    File::seek_static(fd, pos);
    File::write_static(fd, static_cast<const char*>(data), len);
    File::seek_static(fd, orig);
}

size_t check_read(FileDesc fd, off_t pos, void* dst, size_t len)
{
    uint64_t orig = File::get_file_pos(fd);
    File::seek_static(fd, pos);
    size_t ret = File::read_static(fd, static_cast<char*>(dst), len);
    File::seek_static(fd, orig);
    return ret;
}

} // anonymous namespace

AESCryptor::AESCryptor(const uint8_t* key)
    : m_rw_buffer(new char[block_size])
    , m_dst_buffer(new char[block_size])
{
    memcpy(m_aesKey, key, 32);
    memcpy(m_hmacKey, key + 32, 32);

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

void AESCryptor::check_key(const uint8_t* key)
{
    if (memcmp(m_aesKey, key, 32) != 0 || memcmp(m_hmacKey, key + 32, 32) != 0)
        throw DecryptionFailed();
}

void AESCryptor::handle_error()
{
    throw std::runtime_error("Error occurred in encryption layer");
}

void AESCryptor::set_file_size(off_t new_size)
{
    REALM_ASSERT(new_size >= 0 && !int_cast_has_overflow<size_t>(new_size));
    size_t new_size_casted = size_t(new_size);
    size_t block_count = (new_size_casted + block_size - 1) / block_size;
    m_iv_buffer.reserve((block_count + blocks_per_metadata_block - 1) & ~(blocks_per_metadata_block - 1));
}

iv_table& AESCryptor::get_iv_table(FileDesc fd, off_t data_pos, IVLookupMode mode) noexcept
{
    REALM_ASSERT(!int_cast_has_overflow<size_t>(data_pos));
    size_t data_pos_casted = size_t(data_pos);
    size_t idx = data_pos_casted / block_size;
    if (mode == IVLookupMode::UseCache && idx < m_iv_buffer.size())
        return m_iv_buffer[idx];

    size_t block_start = std::min(m_iv_buffer.size(), (idx / blocks_per_metadata_block) * blocks_per_metadata_block);
    size_t block_end = 1 + idx / blocks_per_metadata_block;
    REALM_ASSERT(block_end * blocks_per_metadata_block <= m_iv_buffer.capacity()); // not safe to allocate here
    if (block_end * blocks_per_metadata_block > m_iv_buffer.size()) {
        m_iv_buffer.resize(block_end * blocks_per_metadata_block);
    }

    for (size_t i = block_start; i < block_end * blocks_per_metadata_block; i += blocks_per_metadata_block) {
        off_t iv_pos = iv_table_pos(off_t(i * block_size));
        size_t bytes = check_read(fd, iv_pos, &m_iv_buffer[i], block_size);
        if (bytes < block_size)
            break; // rest is zero-filled by resize()
    }

    return m_iv_buffer[idx];
}

bool AESCryptor::check_hmac(const void* src, size_t len, const uint8_t* hmac) const
{
    uint8_t buffer[224 / 8];
    calc_hmac(src, len, buffer, m_hmacKey);

    // Constant-time memcmp to avoid timing attacks
    uint8_t result = 0;
    for (size_t i = 0; i < 224 / 8; ++i)
        result |= buffer[i] ^ hmac[i];
    return result == 0;
}

size_t AESCryptor::read(FileDesc fd, off_t pos, char* dst, size_t size)
{
    REALM_ASSERT_EX(size % block_size == 0, size, block_size);
    // We need to throw DecryptionFailed if the key is incorrect or there has been a corruption in the data but
    // not in a reader starvation scenario where a different process is writing pages and ivs faster than we can read
    // them. We also want to optimize for a single process writer since in that case all the cached ivs are correct.
    // To do this, we first attempt to use the cached IV, and if it is invalid, read from disk again. During reader
    // starvation, the just read IV could already be out of date with the data page, so continue trying to read until
    // a match is found (for up to 20 seconds before giving up entirely).
    size_t retry_count = 0;
    std::pair<iv_table, size_t> last_iv_and_data_hash;
    auto retry_start_time = std::chrono::steady_clock::now();
    size_t num_identical_reads = 1;
    auto retry = [&](std::string_view page_data, const iv_table& iv, const char* debug_from) {
        constexpr auto max_retry_period = std::chrono::seconds(20);
        auto elapsed = std::chrono::steady_clock::now() - retry_start_time;
        if (elapsed > max_retry_period) {
            auto str = util::format("Reader starvation detected after %1 seconds (retry_count=%2, from=%3, size=%4)",
                                    std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), retry_count,
                                    debug_from, size);
            std::cout << str << std::endl;
            throw DecryptionFailed(str);
        }
        else {
            // don't wait on the first retry as we want to optimize the case where the first read
            // from the iv table cache didn't validate and we are fetching the iv block from disk for the first time
            std::pair<iv_table, size_t> cur_iv_and_data_hash =
                std::make_pair(iv, std::hash<std::string_view>{}(page_data));
            if (retry_count != 0) {
                sched_yield();
                if (last_iv_and_data_hash == cur_iv_and_data_hash) {
                    ++num_identical_reads;
                }
            }
            last_iv_and_data_hash = cur_iv_and_data_hash;
            ++retry_count;
        }
    };

    auto should_retry = [&]() -> bool {
        // if we do not observe identical data or iv within several sequential reads then
        // this is a multiprocess reader starvation scenario so keep trying until we get a match
        return retry_count <= 5 || (retry_count - num_identical_reads > 1 && retry_count < 20);
    };

    size_t bytes_read = 0;
    while (bytes_read < size) {
        ssize_t actual = check_read(fd, real_offset(pos), m_rw_buffer.get(), block_size);

        if (actual == 0)
            return bytes_read;

        iv_table& iv = get_iv_table(fd, pos, retry_count == 0 ? IVLookupMode::UseCache : IVLookupMode::Refetch);
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
                ssize_t i;
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

void AESCryptor::try_read_block(FileDesc fd, off_t pos, char* dst) noexcept
{
    ssize_t bytes_read = check_read(fd, real_offset(pos), m_rw_buffer.get(), block_size);

    if (bytes_read == 0) {
        std::cerr << "Read failed: 0x" << std::hex << pos << std::endl;
        memset(dst, 0x55, block_size);
        return;
    }

    iv_table& iv = get_iv_table(fd, pos, IVLookupMode::Refetch);
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

void AESCryptor::write(FileDesc fd, off_t pos, const char* src, size_t size) noexcept
{
    REALM_ASSERT(size % block_size == 0);
    while (size > 0) {
        iv_table& iv = get_iv_table(fd, pos);

        memcpy(&iv.iv2, &iv.iv1, 32); // this is also copying the hmac
        do {
            ++iv.iv1;
            // 0 is reserved for never-been-used, so bump if we just wrapped around
            if (iv.iv1 == 0)
                ++iv.iv1;

            crypt(mode_Encrypt, pos, m_rw_buffer.get(), src, reinterpret_cast<const char*>(&iv.iv1));
            calc_hmac(m_rw_buffer.get(), block_size, iv.hmac1, m_hmacKey);
            // In the extremely unlikely case that both the old and new versions have
            // the same hash we won't know which IV to use, so bump the IV until
            // they're different.
        } while (REALM_UNLIKELY(memcmp(iv.hmac1, iv.hmac2, 28) == 0));

        check_write(fd, iv_table_pos(pos), &iv, sizeof(iv));
        check_write(fd, real_offset(pos), m_rw_buffer.get(), block_size);

        pos += block_size;
        src += block_size;
        size -= block_size;
    }
}

void AESCryptor::crypt(EncryptionMode mode, off_t pos, char* dst, const char* src, const char* stored_iv) noexcept
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
    if (!EVP_CipherInit_ex(m_ctx, EVP_aes_256_cbc(), NULL, m_aesKey, iv, mode))
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

void AESCryptor::calc_hmac(const void* src, size_t len, uint8_t* dst, const uint8_t* key) const
{
#if REALM_PLATFORM_APPLE
    CCHmac(kCCHmacAlgSHA224, key, 32, src, len, dst);
#else
    uint8_t ipad[64];
    for (size_t i = 0; i < 32; ++i)
        ipad[i] = key[i] ^ 0x36;
    memset(ipad + 32, 0x36, 32);

    uint8_t opad[64] = {0};
    for (size_t i = 0; i < 32; ++i)
        opad[i] = key[i] ^ 0x5C;
    memset(opad + 32, 0x5C, 32);

    // Full hmac operation is sha224(opad + sha224(ipad + data))
#ifdef _WIN32
    sha224_state s;
    sha_init(s);
    sha_process(s, ipad, 64);
    sha_process(s, static_cast<const uint8_t*>(src), uint32_t(len));
    sha_done(s, dst);

    sha_init(s);
    sha_process(s, opad, 64);
    sha_process(s, dst, 28); // 28 == SHA224_DIGEST_LENGTH
    sha_done(s, dst);
#else
    SHA256_CTX ctx;
    SHA224_Init(&ctx);
    SHA256_Update(&ctx, ipad, 64);
    SHA256_Update(&ctx, static_cast<const uint8_t*>(src), len);
    SHA256_Final(dst, &ctx);

    SHA224_Init(&ctx);
    SHA256_Update(&ctx, opad, 64);
    SHA256_Update(&ctx, dst, SHA224_DIGEST_LENGTH);
    SHA256_Final(dst, &ctx);
#endif

#endif
}

EncryptedFileMapping::EncryptedFileMapping(SharedFileInfo& file, size_t file_offset, void* addr, size_t size,
                                           File::AccessMode access)
    : m_file(file)
    , m_page_shift(log2(realm::util::page_size()))
    , m_blocks_per_page(static_cast<size_t>(1ULL << m_page_shift) / block_size)
    , m_num_decrypted(0)
    , m_access(access)
#ifdef REALM_DEBUG
    , m_validate_buffer(new char[static_cast<size_t>(1ULL << m_page_shift)])
#endif
{
    REALM_ASSERT(m_blocks_per_page * block_size == static_cast<size_t>(1ULL << m_page_shift));
    set(addr, size, file_offset); // throws
    file.mappings.push_back(this);
}

EncryptedFileMapping::~EncryptedFileMapping()
{
    for (auto& e : m_page_state) {
        REALM_ASSERT(is_not(e, Writable));
    }
    if (m_access == File::access_ReadWrite) {
        flush();
        sync();
    }
    m_file.mappings.erase(remove(m_file.mappings.begin(), m_file.mappings.end(), this));
}

char* EncryptedFileMapping::page_addr(size_t local_page_ndx) const noexcept
{
    REALM_ASSERT_EX(local_page_ndx < m_page_state.size(), local_page_ndx, m_page_state.size());
    return static_cast<char*>(m_addr) + (local_page_ndx << m_page_shift);
}

void EncryptedFileMapping::mark_outdated(size_t local_page_ndx) noexcept
{
    if (local_page_ndx >= m_page_state.size())
        return;
    REALM_ASSERT(is_not(m_page_state[local_page_ndx], UpToDate));
    REALM_ASSERT(is_not(m_page_state[local_page_ndx], Dirty));
    REALM_ASSERT(is_not(m_page_state[local_page_ndx], Writable));

    size_t chunk_ndx = local_page_ndx >> page_to_chunk_shift;
    if (m_chunk_dont_scan[chunk_ndx])
        m_chunk_dont_scan[chunk_ndx] = 0;
}

bool EncryptedFileMapping::copy_up_to_date_page(size_t local_page_ndx) noexcept
{
    REALM_ASSERT_EX(local_page_ndx < m_page_state.size(), local_page_ndx, m_page_state.size());
    // Precondition: this method must never be called for a page which
    // is already up to date.
    REALM_ASSERT(is_not(m_page_state[local_page_ndx], UpToDate));
    for (size_t i = 0; i < m_file.mappings.size(); ++i) {
        EncryptedFileMapping* m = m_file.mappings[i];
        size_t page_ndx_in_file = local_page_ndx + m_first_page;
        if (m == this || !m->contains_page(page_ndx_in_file))
            continue;

        size_t shadow_mapping_local_ndx = page_ndx_in_file - m->m_first_page;
        if (is(m->m_page_state[shadow_mapping_local_ndx], UpToDate)) {
            memcpy(page_addr(local_page_ndx), m->page_addr(shadow_mapping_local_ndx),
                   static_cast<size_t>(1ULL << m_page_shift));
            return true;
        }
    }
    return false;
}

void EncryptedFileMapping::refresh_page(size_t local_page_ndx, size_t required)
{
    REALM_ASSERT_EX(local_page_ndx < m_page_state.size(), local_page_ndx, m_page_state.size());
    REALM_ASSERT(is_not(m_page_state[local_page_ndx], Dirty));
    REALM_ASSERT(is_not(m_page_state[local_page_ndx], Writable));
    char* addr = page_addr(local_page_ndx);

    if (!copy_up_to_date_page(local_page_ndx)) {
        size_t page_ndx_in_file = local_page_ndx + m_first_page;
        size_t size = static_cast<size_t>(1ULL << m_page_shift);
        size_t actual = m_file.cryptor.read(m_file.fd, off_t(page_ndx_in_file << m_page_shift), addr, size);
        if (actual < size) {
            if (actual >= required) {
                memset(addr + actual, 0x55, size - actual);
            }
            else {
                throw DecryptionFailed();
            }
        }
    }
    if (is_not(m_page_state[local_page_ndx], UpToDate | RefetchRequired))
        m_num_decrypted++;
    clear(m_page_state[local_page_ndx], RefetchRequired);
    set(m_page_state[local_page_ndx], UpToDate);
}

void EncryptedFileMapping::mark_for_refresh(size_t ref_start, size_t ref_end)
{
    size_t first_page_ndx = ref_start >> m_page_shift;
    size_t last_page_ndx = (ref_end - 1) >> m_page_shift; // FIXME: why - 1 ?
    for (size_t page_ndx = first_page_ndx; page_ndx <= last_page_ndx; ++page_ndx) {
        for (size_t i = 0; i < m_file.mappings.size(); ++i) {
            EncryptedFileMapping* m = m_file.mappings[i];
            if (m->contains_page(page_ndx)) {
                size_t local_page_ndx = page_ndx - m->m_first_page;
                if (is(m->m_page_state[local_page_ndx], UpToDate)) {
                    // if we collide with a concurrent write (state Writable) we cannot mark
                    // the page for refresh. If we did, it might be refreshed and any partial
                    // write would be lost.
                    // Same goes for an already written page (state Dirty).
                    // However: The reader triggering the mark for refresh is doing so before
                    // the write has completed (or the page would have been flushed and in UpToDate state),
                    // so the reader cannot be meant to see the write. The write may be to the same
                    // page, but it cannot be to the part of the page that the reader requests.
                    // - the real problem: we may need to refresh this page due to an earlier
                    //   write which the reader *must* see, but collide with a later writer which
                    // we must not overwrite.
                    //
                    // Does the following argument save the day?
                    // Every writer to a page must have refreshed that page as part of executing
                    // a read barrier. This, it the writer must have done while holding the write
                    // lock. Consequently the page must already have been refreshed up to the version
                    // which a reader is requesting. The reader may have deferred mark for request,
                    // but it actually does not need it.
                    // a) there must be a read_barrier for every write_barrier
                    // b) the writer mush have marked pages for refresh up till latest version,
                    // c) it must have done so while holding the write lock
                    // Are a/b/c fullfilled?  Are they sufficient?
                    if (is_not(m->m_page_state[local_page_ndx], Dirty | Writable)) {
                        clear(m->m_page_state[local_page_ndx], UpToDate);
                        set(m->m_page_state[local_page_ndx], RefetchRequired);
                    }
                }
            }
        }
    }
}

void EncryptedFileMapping::write_and_update_all(size_t local_page_ndx, size_t begin_offset,
                                                size_t end_offset) noexcept
{
    REALM_ASSERT(is(m_page_state[local_page_ndx], Writable));
    REALM_ASSERT(is(m_page_state[local_page_ndx], UpToDate));
    // Go through all other mappings of this file and copy changes into those mappings
    size_t page_ndx_in_file = local_page_ndx + m_first_page;
    for (size_t i = 0; i < m_file.mappings.size(); ++i) {
        EncryptedFileMapping* m = m_file.mappings[i];
        if (m != this && m->contains_page(page_ndx_in_file)) {
            size_t shadow_local_page_ndx = page_ndx_in_file - m->m_first_page;
            if (is(m->m_page_state[shadow_local_page_ndx], UpToDate)) { // only keep up to data pages up to date
                memcpy(m->page_addr(shadow_local_page_ndx) + begin_offset, page_addr(local_page_ndx) + begin_offset,
                       end_offset - begin_offset);
            }
            else {
                m->mark_outdated(shadow_local_page_ndx);
            }
        }
    }
    set(m_page_state[local_page_ndx], Dirty);
    clear(m_page_state[local_page_ndx], Writable);
    size_t chunk_ndx = local_page_ndx >> page_to_chunk_shift;
    if (m_chunk_dont_scan[chunk_ndx])
        m_chunk_dont_scan[chunk_ndx] = 0;
}


void EncryptedFileMapping::validate_page(size_t local_page_ndx) noexcept
{
#ifdef REALM_DEBUG
    REALM_ASSERT(local_page_ndx < m_page_state.size());
    if (is_not(m_page_state[local_page_ndx], UpToDate))
        return;

    const size_t page_ndx_in_file = local_page_ndx + m_first_page;
    if (!m_file.cryptor.read(m_file.fd, off_t(page_ndx_in_file << m_page_shift), m_validate_buffer.get(),
                             static_cast<size_t>(1ULL << m_page_shift)))
        return;

    for (size_t i = 0; i < m_file.mappings.size(); ++i) {
        EncryptedFileMapping* m = m_file.mappings[i];
        size_t shadow_mapping_local_ndx = page_ndx_in_file - m->m_first_page;
        if (m != this && m->contains_page(page_ndx_in_file) && is(m->m_page_state[shadow_mapping_local_ndx], Dirty)) {
            memcpy(m_validate_buffer.get(), m->page_addr(shadow_mapping_local_ndx),
                   static_cast<size_t>(1ULL << m_page_shift));
            break;
        }
    }

    if (memcmp(m_validate_buffer.get(), page_addr(local_page_ndx), static_cast<size_t>(1ULL << m_page_shift))) {
        std::cerr << "mismatch " << this << ": fd(" << m_file.fd << ")"
                  << "page(" << local_page_ndx << "/" << m_page_state.size() << ") " << m_validate_buffer.get() << " "
                  << page_addr(local_page_ndx) << std::endl;
        REALM_TERMINATE("");
    }
#else
    static_cast<void>(local_page_ndx);
#endif
}

void EncryptedFileMapping::validate() noexcept
{
#ifdef REALM_DEBUG
    const size_t num_local_pages = m_page_state.size();
    for (size_t local_page_ndx = 0; local_page_ndx < num_local_pages; ++local_page_ndx)
        validate_page(local_page_ndx);
#endif
}

void EncryptedFileMapping::reclaim_page(size_t page_ndx)
{
#ifdef _WIN32
    // On windows we don't know how to replace a page within a page range with a fresh one.
    // instead we clear it. If the system runs with same-page-merging, this will reduce
    // the number of used pages.
    memset(page_addr(page_ndx), 0, static_cast<size_t>(1) << m_page_shift);
#else
    // On Posix compatible, we can request a new page in the middle of an already
    // requested range, so that's what we do. This releases the backing store for the
    // old page and gives us a shared zero-page that we can later demand-allocate, thus
    // reducing the overall amount of used physical pages.
    void* addr = page_addr(page_ndx);
    void* addr2 = ::mmap(addr, 1 << m_page_shift, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (addr != addr2) {
        if (addr2 == 0)
            throw std::system_error(errno, std::system_category(), std::string("using mmap() to clear page failed"));
        else
            throw std::runtime_error("internal error in mmap()");
    }
#endif
}

/* This functions is a bit convoluted. It reclaims pages, but only does a limited amount of work
 * each time it's called. It saves the progress in a 'progress_ptr' so that it can resume later
 * from where it was stopped.
 *
 * The workload is composed of workunits, each unit signifying
 * 1) A scanning of the state of 4K pages
 * 2) One system call (to mmap to release a page and get a new one)
 * 3) A scanning of 1K entries in the "don't scan" array (corresponding to 4M pages)
 * Approximately
 */
void EncryptedFileMapping::reclaim_untouched(size_t& progress_index, size_t& work_limit) noexcept
{
    const auto scan_amount_per_workunit = 4096;
    bool contiguous_scan = false;
    size_t next_scan_payment = scan_amount_per_workunit;
    const size_t last_index = get_end_index();

    auto done_some_work = [&]() {
        if (work_limit > 0)
            work_limit--;
    };

    auto visit_and_potentially_reclaim = [&](size_t page_ndx) {
        PageState& ps = m_page_state[page_ndx];
        if (is(ps, UpToDate | RefetchRequired)) {
            if (is_not(ps, Touched) && is_not(ps, Dirty) && is_not(ps, Writable)) {
                clear(ps, UpToDate | RefetchRequired);
                reclaim_page(page_ndx);
                m_num_decrypted--;
                done_some_work();
            }
            contiguous_scan = false;
        }
        clear(ps, Touched);
    };

    auto skip_chunk_if_possible = [&](size_t& page_ndx) // update vars corresponding to skipping a chunk if possible
    {
        size_t chunk_ndx = page_ndx >> page_to_chunk_shift;
        if (m_chunk_dont_scan[chunk_ndx]) {
            // skip to end of chunk
            page_ndx = ((chunk_ndx + 1) << page_to_chunk_shift) - 1;
            progress_index = m_first_page + page_ndx;
            // postpone next scan payment
            next_scan_payment += page_to_chunk_factor;
            return true;
        }
        else
            return false;
    };

    auto is_last_page_in_chunk = [](size_t page_ndx) {
        auto page_to_chunk_mask = page_to_chunk_factor - 1;
        return (page_ndx & page_to_chunk_mask) == page_to_chunk_mask;
    };
    auto is_first_page_in_chunk = [](size_t page_ndx) {
        auto page_to_chunk_mask = page_to_chunk_factor - 1;
        return (page_ndx & page_to_chunk_mask) == 0;
    };

    while (work_limit > 0 && progress_index < last_index) {
        size_t page_ndx = progress_index - m_first_page;
        if (!skip_chunk_if_possible(page_ndx)) {
            if (is_first_page_in_chunk(page_ndx)) {
                contiguous_scan = true;
            }
            visit_and_potentially_reclaim(page_ndx);
            // if we've scanned a full chunk contiguously, mark it as not needing scans
            if (is_last_page_in_chunk(page_ndx)) {
                if (contiguous_scan) {
                    m_chunk_dont_scan[page_ndx >> page_to_chunk_shift] = 1;
                }
                contiguous_scan = false;
            }
        }
        // account for work performed:
        if (page_ndx >= next_scan_payment) {
            next_scan_payment = page_ndx + scan_amount_per_workunit;
            done_some_work();
        }
        ++progress_index;
    }
    return;
}

void EncryptedFileMapping::flush() noexcept
{
    const size_t num_dirty_pages = m_page_state.size();
#ifdef REALM_DEBUG
    uint64_t pages_written = 0;
#endif
    for (size_t local_page_ndx = 0; local_page_ndx < num_dirty_pages; ++local_page_ndx) {
        if (is_not(m_page_state[local_page_ndx], Dirty)) {
            validate_page(local_page_ndx);
            continue;
        }

        size_t page_ndx_in_file = local_page_ndx + m_first_page;
        m_file.cryptor.write(m_file.fd, off_t(page_ndx_in_file << m_page_shift), page_addr(local_page_ndx),
                             static_cast<size_t>(1ULL << m_page_shift));
        clear(m_page_state[local_page_ndx], Dirty);
#ifdef REALM_DEBUG
        if (page_ndx_in_file < 64) {
            pages_written |= (1 << page_ndx_in_file);
        }
#endif
    }
#ifdef REALM_DEBUG
    if (pages_written > 0 && m_file.validator.is_attached()) {
        m_file.validator.seek(m_file.validator.get_size());
        auto msg = util::format("wrote pages: bitwise[%1] at indices: ", pages_written);
        for (size_t i = 0; i < 64; ++i) {
            if ((pages_written & (uint64_t(1) << i)) > 0) {
                msg += util::format("%1%2", i == 0 ? "" : ", ", i);
            }
        }
        msg += std::string("\n");
        m_file.validator.write(msg.data(), msg.size());
    }
#endif // REALM_DEBUG

    validate();
}

#ifdef _MSC_VER
#pragma warning(disable : 4297) // throw in noexcept
#endif
void EncryptedFileMapping::sync() noexcept
{
#ifdef _WIN32
    if (FlushFileBuffers(m_file.fd))
        return;
    throw std::system_error(GetLastError(), std::system_category(), "FlushFileBuffers() failed");
#else
    fsync(m_file.fd);
    // FIXME: on iOS/OSX fsync may not be enough to ensure crash safety.
    // Consider adding fcntl(F_FULLFSYNC). This most likely also applies to msync.
    //
    // See description of fsync on iOS here:
    // https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html
    //
    // See also
    // https://developer.apple.com/library/ios/documentation/Cocoa/Conceptual/CoreData/Articles/cdPersistentStores.html
    // for a discussion of this related to core data.
#endif
}
#ifdef _MSC_VER
#pragma warning(default : 4297)
#endif

void EncryptedFileMapping::write_barrier(const void* addr, size_t size) noexcept
{
    // Propagate changes to all other decrypted pages mapping the same memory

    REALM_ASSERT(m_access == File::access_ReadWrite);
    size_t first_accessed_local_page = get_local_index_of_address(addr);
    size_t first_offset = static_cast<const char*>(addr) - page_addr(first_accessed_local_page);
    const char* last_accessed_address = static_cast<const char*>(addr) + (size == 0 ? 0 : size - 1);
    size_t last_accessed_local_page = get_local_index_of_address(last_accessed_address);
    size_t pages_size = m_page_state.size();

    // propagate changes to first page (update may be partial, may also be to last page)
    if (first_accessed_local_page < pages_size) {
        REALM_ASSERT_EX(is(m_page_state[first_accessed_local_page], UpToDate),
                        m_page_state[first_accessed_local_page]);
        if (first_accessed_local_page == last_accessed_local_page) {
            size_t last_offset = last_accessed_address - page_addr(first_accessed_local_page);
            write_and_update_all(first_accessed_local_page, first_offset, last_offset + 1);
        }
        else
            write_and_update_all(first_accessed_local_page, first_offset, static_cast<size_t>(1) << m_page_shift);
    }
    // propagate changes to pages between first and last page (update only full pages)
    for (size_t idx = first_accessed_local_page + 1; idx < last_accessed_local_page && idx < pages_size; ++idx) {
        REALM_ASSERT(is(m_page_state[idx], UpToDate));
        write_and_update_all(idx, 0, static_cast<size_t>(1) << m_page_shift);
    }
    // propagate changes to the last page (update may be partial)
    if (first_accessed_local_page < last_accessed_local_page && last_accessed_local_page < pages_size) {
        REALM_ASSERT(is(m_page_state[last_accessed_local_page], UpToDate));
        size_t last_offset = last_accessed_address - page_addr(last_accessed_local_page);
        write_and_update_all(last_accessed_local_page, 0, last_offset + 1);
    }
}

void EncryptedFileMapping::read_barrier(const void* addr, size_t size, Header_to_size header_to_size, bool to_modify)
{
    size_t first_accessed_local_page = get_local_index_of_address(addr);
    size_t page_size = 1ULL << m_page_shift;
    size_t required =
        ((reinterpret_cast<uintptr_t>(addr) - reinterpret_cast<uintptr_t>(m_addr)) & (page_size - 1)) + size;
    {
        // make sure the first page is available
        PageState& ps = m_page_state[first_accessed_local_page];
        if (is_not(ps, Touched))
            set(ps, Touched);
        if (is_not(ps, UpToDate))
            refresh_page(first_accessed_local_page, to_modify ? 0 : required);
        if (to_modify)
            set(ps, Writable);
    }

    // force the page reclaimer to look into pages in this chunk:
    size_t chunk_ndx = first_accessed_local_page >> page_to_chunk_shift;
    if (m_chunk_dont_scan[chunk_ndx])
        m_chunk_dont_scan[chunk_ndx] = 0;

    if (header_to_size) {
        // We know it's an array, and array headers are 8-byte aligned, so it is
        // included in the first page which was handled above.
        size = header_to_size(static_cast<const char*>(addr));
    }

    size_t last_idx = get_local_index_of_address(addr, size == 0 ? 0 : size - 1);
    size_t pages_size = m_page_state.size();

    // We already checked first_accessed_local_page above, so we start the loop
    // at first_accessed_local_page + 1 to check the following page.
    for (size_t idx = first_accessed_local_page + 1; idx <= last_idx && idx < pages_size; ++idx) {
        required -= page_size;
        // force the page reclaimer to look into pages in this chunk
        chunk_ndx = idx >> page_to_chunk_shift;
        if (m_chunk_dont_scan[chunk_ndx])
            m_chunk_dont_scan[chunk_ndx] = 0;

        PageState& ps = m_page_state[idx];
        if (is_not(ps, Touched))
            set(ps, Touched);
        if (is_not(ps, UpToDate))
            refresh_page(idx, to_modify ? 0 : required);
        if (to_modify)
            set(ps, Writable);
    }
}

void EncryptedFileMapping::extend_to(size_t offset, size_t new_size)
{
    REALM_ASSERT(new_size % (1ULL << m_page_shift) == 0);
    size_t num_pages = new_size >> m_page_shift;
    m_page_state.resize(num_pages, PageState::Clean);
    m_chunk_dont_scan.resize((num_pages + page_to_chunk_factor - 1) >> page_to_chunk_shift, false);
    m_file.cryptor.set_file_size((off_t)(offset + new_size));
}

void EncryptedFileMapping::set(void* new_addr, size_t new_size, size_t new_file_offset)
{
    REALM_ASSERT(new_file_offset % (1ULL << m_page_shift) == 0);
    REALM_ASSERT(new_size % (1ULL << m_page_shift) == 0);

    // This seems dangerous - correct operation in a setting with multiple (partial)
    // mappings of the same file would rely on ordering of individual mapping requests.
    // Currently we only ever extend the file - but when we implement continuous defrag,
    // this design should be revisited.
    m_file.cryptor.set_file_size(off_t(new_size + new_file_offset));

    flush();
    m_addr = new_addr;

    m_first_page = new_file_offset >> m_page_shift;
    size_t num_pages = new_size >> m_page_shift;

    m_num_decrypted = 0;
    m_page_state.clear();
    m_chunk_dont_scan.clear();

    m_page_state.resize(num_pages, PageState(0));
    m_chunk_dont_scan.resize((num_pages + page_to_chunk_factor - 1) >> page_to_chunk_shift, false);
}

File::SizeType encrypted_size_to_data_size(File::SizeType size) noexcept
{
    if (size == 0)
        return 0;
    return fake_offset(size);
}

File::SizeType data_size_to_encrypted_size(File::SizeType size) noexcept
{
    size_t ps = page_size();
    return real_offset((size + ps - 1) & ~(ps - 1));
}

#else

File::SizeType encrypted_size_to_data_size(File::SizeType size) noexcept
{
    return size;
}

File::SizeType data_size_to_encrypted_size(File::SizeType size) noexcept
{
    return size;
}

#endif // REALM_ENABLE_ENCRYPTION

} // namespace realm::util

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

#include "testsettings.hpp"

#if defined(TEST_ENCRYPTED_FILE_MAPPING)

#include <realm.hpp>
#include <realm/util/aes_cryptor.hpp>
#include <realm/util/encrypted_file_mapping.hpp>
#include <realm/util/file.hpp>

#include "test.hpp"

// Test independence and thread-safety
// -----------------------------------
//
// All tests must be thread safe and independent of each other. This
// is required because it allows for both shuffling of the execution
// order and for parallelized testing.
//
// In particular, avoid using std::rand() since it is not guaranteed
// to be thread safe. Instead use the API offered in
// `test/util/random.hpp`.
//
// All files created in tests must use the TEST_PATH macro (or one of
// its friends) to obtain a suitable file system path. See
// `test/util/test_path.hpp`.
//
//
// Debugging and the ONLY() macro
// ------------------------------
//
// A simple way of disabling all tests except one called `Foo`, is to
// replace TEST(Foo) with ONLY(Foo) and then recompile and rerun the
// test suite. Note that you can also use filtering by setting the
// environment varible `UNITTEST_FILTER`. See `README.md` for more on
// this.
//
// Another way to debug a particular test, is to copy that test into
// `experiments/testcase.cpp` and then run `sh build.sh
// check-testcase` (or one of its friends) from the command line.

#if REALM_ENABLE_ENCRYPTION

using namespace realm;
using namespace realm::util;
using realm::FileDesc;

namespace {
const char test_key[] = "1234567890123456789012345678901123456789012345678901234567890123";
}

TEST(EncryptedFile_CryptorBasic)
{
    TEST_PATH(path);

    AESCryptor cryptor(test_key);
    cryptor.set_file_size(16);
    const char data[4096] = "test data";
    char buffer[4096];

    File file(path, realm::util::File::mode_Write);
    cryptor.write(file.get_descriptor(), 0, data, sizeof(data));
    cryptor.read(file.get_descriptor(), 0, buffer, sizeof(buffer));
    CHECK(memcmp(buffer, data, strlen(data)) == 0);
}

TEST(EncryptedFile_CryptorRepeatedWrites)
{
    TEST_PATH(path);
    AESCryptor cryptor(test_key);
    cryptor.set_file_size(16);

    const char data[4096] = "test data";
    char raw_buffer_1[8192] = {0}, raw_buffer_2[8192] = {0};
    File file(path, realm::util::File::mode_Write);

    cryptor.write(file.get_descriptor(), 0, data, sizeof(data));
    ssize_t actual_read_1 = file.read(0, raw_buffer_1, sizeof(raw_buffer_1));
    CHECK_EQUAL(actual_read_1, sizeof(raw_buffer_1));

    cryptor.write(file.get_descriptor(), 0, data, sizeof(data));
    ssize_t actual_read_2 = file.read(0, raw_buffer_2, sizeof(raw_buffer_2));
    CHECK_EQUAL(actual_read_2, sizeof(raw_buffer_2));

    CHECK(memcmp(raw_buffer_1, raw_buffer_2, sizeof(raw_buffer_1)) != 0);
}

TEST(EncryptedFile_SeparateCryptors)
{
    TEST_PATH(path);

    const char data[4096] = "test data";
    char buffer[4096];

    File file(path, realm::util::File::mode_Write);
    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(16);
        cryptor.write(file.get_descriptor(), 0, data, sizeof(data));
    }
    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(16);
        cryptor.read(file.get_descriptor(), 0, buffer, sizeof(buffer));
    }

    CHECK(memcmp(buffer, data, strlen(data)) == 0);
}

TEST(EncryptedFile_InterruptedWrite)
{
    TEST_PATH(path);

    const char data[4096] = "test data";

    File file(path, realm::util::File::mode_Write);
    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(16);
        cryptor.write(file.get_descriptor(), 0, data, sizeof(data));
    }

    // Fake an interrupted write which updates the IV table but not the data
    char buffer[4096];
    size_t actual_pread = file.read(0, buffer, 64);
    CHECK_EQUAL(actual_pread, 64);

    memcpy(buffer + 32, buffer, 32);
    buffer[5]++; // first byte of "hmac1" field in iv table
    file.write(0, buffer, 64);

    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(16);
        cryptor.read(file.get_descriptor(), 0, buffer, sizeof(buffer));
        CHECK(memcmp(buffer, data, strlen(data)) == 0);
    }
}

TEST(EncryptedFile_LargePages)
{
    TEST_PATH(path);

    char data[4096 * 4];
    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = static_cast<char>(i);

    AESCryptor cryptor(test_key);
    cryptor.set_file_size(sizeof(data));
    char buffer[sizeof(data)];

    File file(path, realm::util::File::mode_Write);
    cryptor.write(file.get_descriptor(), 0, data, sizeof(data));
    cryptor.read(file.get_descriptor(), 0, buffer, sizeof(buffer));
    CHECK(memcmp(buffer, data, sizeof(data)) == 0);
}

TEST(EncryptedFile_IVRefreshing)
{
    constexpr size_t block_size = 4096;
    constexpr size_t blocks_per_metadata_block = 64;

    auto verify_states = [&](const std::vector<IVRefreshState>& states, const std::vector<bool>& expect_refresh) {
        if (!CHECK_EQUAL(states.size(), expect_refresh.size()))
            return;
        for (size_t i = 0; i < expect_refresh.size(); ++i)
            CHECK_EQUAL(states[i] == IVRefreshState::RequiresRefresh, expect_refresh[i]);
    };

    // enough data to span two metadata blocks
    constexpr size_t data_size = block_size * blocks_per_metadata_block * 2;
    constexpr size_t num_blocks = data_size / block_size;
    char data[block_size];
    std::iota(std::begin(data), std::end(data), 0);

    TEST_PATH(path);
    File file(path, realm::util::File::mode_Write);
    const FileDesc fd = file.get_descriptor();

    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        for (size_t i = 0; i < data_size; i += block_size) {
            cryptor.write(fd, off_t(i), data, block_size);
        }
    }

    {
        // First check basic bulk updating. Requesting the entire range of blocks
        // should update only the first metablock. The first call will report
        // that every block needs to be refreshed, and then the second will
        // report that they're all up-to-date
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        verify_states(cryptor.refresh_ivs(fd, 0, num_blocks), std::vector<bool>(blocks_per_metadata_block, true));
        verify_states(cryptor.refresh_ivs(fd, 0, num_blocks), std::vector<bool>(blocks_per_metadata_block, false));

        // Check that the second metablock behaves the same way when we set the
        // the offset
        verify_states(cryptor.refresh_ivs(fd, blocks_per_metadata_block, num_blocks),
                      std::vector<bool>(blocks_per_metadata_block, true));
        verify_states(cryptor.refresh_ivs(fd, blocks_per_metadata_block, num_blocks),
                      std::vector<bool>(blocks_per_metadata_block, false));
    }

    {
        // Check that non-metablock aligned begin and end are honored. Even
        // though we read 64 IVs at a time, only exactly the one we used should
        // be cached as otherwise we could miss updates.
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        for (size_t i = 0; i < num_blocks; ++i) {
            verify_states(cryptor.refresh_ivs(fd, i, i + 1), std::vector<bool>(1, true));
        }
        for (size_t i = 0; i < num_blocks; ++i) {
            verify_states(cryptor.refresh_ivs(fd, i, i + 1), std::vector<bool>(1, false));
        }
    }

    {
        // Loop backwards to verify we don't accidentally use IVs before the
        // requested one either
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        for (size_t i = num_blocks; i > 0; --i) {
            verify_states(cryptor.refresh_ivs(fd, i - 1, i), std::vector<bool>(1, true));
        }
        for (size_t i = num_blocks; i > 0; --i) {
            verify_states(cryptor.refresh_ivs(fd, i - 1, i), std::vector<bool>(1, false));
        }
    }

    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        // Refresh request in the middle of a metablock only fills up to the
        // end of that metablock
        verify_states(cryptor.refresh_ivs(fd, blocks_per_metadata_block / 4, num_blocks),
                      std::vector<bool>(blocks_per_metadata_block * 3 / 4, true));
        // Refresh request ending past the end of the file fills to the end of
        // the file
        size_t offset = blocks_per_metadata_block + 21;
        verify_states(cryptor.refresh_ivs(fd, offset, num_blocks), std::vector<bool>(num_blocks - offset, true));

        // Reading IVs corresponding to blocks past the end of the file is allowed
        cryptor.set_file_size(off_t(data_size * 3 / 4));
        std::vector<bool> expected(blocks_per_metadata_block, true);
        std::fill(expected.begin() + 21, expected.end(), false);
        verify_states(cryptor.refresh_ivs(fd, blocks_per_metadata_block, num_blocks), expected);
    }

    // Note that while this does not modify the plaintext, it does result in
    // entirely new encrypted data being produced for each block (which is one
    // of the points of incrementing the IV each write)
    auto make_external_write_at_pos = [&](off_t data_pos) {
        const off_t write_block_pos = round_down(data_pos, block_size);
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        cryptor.write(fd, off_t(write_block_pos), data, block_size);
    };

    {
        AESCryptor cryptor(test_key);
        cryptor.set_file_size(off_t(data_size));
        cryptor.refresh_ivs(fd, 0, num_blocks);
        cryptor.refresh_ivs(fd, blocks_per_metadata_block, num_blocks);

        // Touch each block and verify that the block needs to refreshed when
        // checking just that block
        for (size_t block = 0; block < num_blocks; ++block) {
            make_external_write_at_pos(block * block_size);
            verify_states(cryptor.refresh_ivs(fd, block, block + 1), std::vector<bool>(1, true));
            verify_states(cryptor.refresh_ivs(fd, block, block + 1), std::vector<bool>(1, false));
        }

        // Touch each block and verify that the block needs to refreshed when
        // checking the entire metablock
        for (size_t block = 0; block < num_blocks; ++block) {
            make_external_write_at_pos(block * block_size);
            std::vector<bool> expected(blocks_per_metadata_block, false);
            expected[block % blocks_per_metadata_block] = true;
            verify_states(cryptor.refresh_ivs(fd, round_down(block, blocks_per_metadata_block), num_blocks),
                          expected);
            expected[block % blocks_per_metadata_block] = false;
            verify_states(cryptor.refresh_ivs(fd, round_down(block, blocks_per_metadata_block), num_blocks),
                          expected);
        }

        // Touch each block and verify that the block needs to refreshed when
        // checking the entire metablock, starting from the touched block
        for (size_t block = 0; block < num_blocks; ++block) {
            make_external_write_at_pos(block * block_size);

            size_t index_in_metablock = block % blocks_per_metadata_block;
            std::vector<bool> expected(blocks_per_metadata_block - index_in_metablock, false);
            expected[0] = true;
            verify_states(cryptor.refresh_ivs(fd, block, num_blocks), expected);
            expected[0] = false;
            verify_states(cryptor.refresh_ivs(fd, block, num_blocks), expected);
        }
    }
}

static void check_attach_and_read(const char* key, const std::string& path, size_t num_entries)
{
    try {
        auto hist = make_in_realm_history();
        DBOptions options(key);
        auto sg = DB::create(*hist, path, options);
        auto rt = sg->start_read();
        auto foo = rt->get_table("foo");
        auto pk_col = foo->get_primary_key_column();
        REALM_ASSERT_3(foo->size(), ==, num_entries);
        REALM_ASSERT_3(foo->where().equal(pk_col, util::format("name %1", num_entries - 1).c_str()).count(), ==, 1);
    }
    catch (const std::exception& e) {
        auto fs = File::get_size_static(path);
        util::format(std::cout, "Error for num_entries %1 with page_size of %2 on file of size %3\n%4", num_entries,
                     page_size(), fs, e.what());
        throw;
    }
}

// This test changes the global page_size() and should not run with other tests.
// It checks that an encrypted Realm is portable between systems with a different page size
NONCONCURRENT_TEST(EncryptedFile_Portablility)
{
    const char* key = test_util::crypt_key(true);
    // The idea here is to incrementally increase the allocations in the Realm
    // such that the top ref written eventually crosses over the block_size and
    // page_size() thresholds. This has caught faulty top_ref + size calculations.
    std::vector<size_t> test_sizes;
#if TEST_DURATION == 0
    test_sizes.resize(100);
    std::iota(test_sizes.begin(), test_sizes.end(), 500);
    // The allocations are not controlled, but at the time of writing this test
    // 539 objects produced a file of size 16384 while 540 objects produced a file of size 20480
    // so at least one threshold is crossed here, though this may change if the allocator changes
    // or if compression is implemented
#else
    test_sizes.resize(5000);
    std::iota(test_sizes.begin(), test_sizes.end(), 500);
#endif

    test_sizes.push_back(1); // check the lower limit
    for (auto num_entries : test_sizes) {
        TEST_PATH(path);
        {
            // create the Realm with the smallest supported page_size() of 4096
            OnlyForTestingPageSizeChange change_page_size(4096);
            Group g;
            TableRef foo = g.add_table_with_primary_key("foo", type_String, "name", false);
            for (size_t i = 0; i < num_entries; ++i) {
                foo->create_object_with_primary_key(util::format("name %1", i));
            }
            g.write(path, key);
            // size_t fs = File::get_size_static(path);
            // util::format(std::cout, "write of %1 objects produced a file of size %2\n", num_entries, fs);
        }
        {
            OnlyForTestingPageSizeChange change_page_size(8192);
            check_attach_and_read(key, path, num_entries);
        }
        {
            OnlyForTestingPageSizeChange change_page_size(16384);
            check_attach_and_read(key, path, num_entries);
        }

        // check with the native page_size (which is probably redundant with one of the above)
        // and check that a write works correctly
        auto history = make_in_realm_history();
        DBOptions options(key);
        DBRef db = DB::create(*history, path, options);
        auto wt = db->start_write();
        TableRef bar = wt->get_or_add_table_with_primary_key("bar", type_String, "pk");
        bar->create_object_with_primary_key("test");
        wt->commit();
        check_attach_and_read(key, path, num_entries);
    }
}

#endif // REALM_ENABLE_ENCRYPTION
#endif // TEST_ENCRYPTED_FILE_MAPPING

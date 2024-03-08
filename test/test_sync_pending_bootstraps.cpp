#include "realm/db.hpp"
#include "realm/sync/noinst/client_history_impl.hpp"
#include "realm/sync/noinst/pending_bootstrap_store.hpp"

#include "test.hpp"
#include "util/test_path.hpp"

namespace realm::sync {

TEST(Sync_PendingBootstrapStoreBatching)
{
    SHARED_GROUP_TEST_PATH(db_path);
    SyncProgress progress;
    progress.download = {3, 5};
    progress.latest_server_version = {5, 123456789};
    progress.upload = {5, 5};
    {
        auto db = DB::create(make_client_replication(), db_path);
        sync::PendingBootstrapStore store(db, *test_context.logger);

        CHECK_NOT(store.has_pending());
        CHECK_NOT(store.query_version());
        CHECK_NOT(store.remote_version());

        std::vector<RemoteChangeset> changesets;
        std::vector<std::string> changeset_data;

        changeset_data.emplace_back(1024, 'a');
        changesets.emplace_back(3, 6, BinaryData(changeset_data.back()), 1, 1);
        changesets.back().original_changeset_size = 1024;
        changeset_data.emplace_back(1024, 'b');
        changesets.emplace_back(3, 7, BinaryData(changeset_data.back()), 2, 1);
        changesets.back().original_changeset_size = 1024;
        changeset_data.emplace_back(1024, 'c');
        changesets.emplace_back(3, 8, BinaryData(changeset_data.back()), 3, 1);
        changesets.back().original_changeset_size = 1024;

        bool created_new_batch = false;
        store.add_batch(1, 3, util::none, changesets, &created_new_batch);

        CHECK(created_new_batch);
        CHECK_NOT(store.has_pending());
        CHECK(store.query_version());
        CHECK(store.remote_version());
        CHECK_EQUAL(*store.query_version(), 1);
        CHECK_EQUAL(*store.remote_version(), 3);

        changesets.clear();
        changeset_data.clear();
        changeset_data.emplace_back(1024, 'd');
        changesets.emplace_back(3, 9, BinaryData(changeset_data.back()), 4, 2);
        changesets.back().original_changeset_size = 1024;
        changeset_data.emplace_back(1024, 'e');
        changesets.emplace_back(3, 10, BinaryData(changeset_data.back()), 5, 3);
        changesets.back().original_changeset_size = 1024;

        store.add_batch(1, 3, progress, changesets, &created_new_batch);
        CHECK_NOT(created_new_batch);
        CHECK(store.has_pending());
    }

    {
        auto db = DB::create(make_client_replication(), db_path);
        sync::PendingBootstrapStore store(db, *test_context.logger);
        CHECK(store.has_pending());
        CHECK(store.query_version());
        CHECK(store.remote_version());
        CHECK_EQUAL(*store.query_version(), 1);
        CHECK_EQUAL(*store.remote_version(), 3);

        auto stats = store.pending_stats();
        CHECK_EQUAL(stats.pending_changeset_bytes, 1024 * 5);
        CHECK_EQUAL(stats.pending_changesets, 5);
        CHECK_EQUAL(stats.query_version, 1);
        CHECK_EQUAL(stats.remote_version, 3);

        auto pending_batch = store.peek_pending((1024 * 3) - 1);
        CHECK_EQUAL(pending_batch.changesets.size(), 3);
        CHECK_EQUAL(pending_batch.remaining_changesets, 2);
        CHECK_EQUAL(pending_batch.query_version, 1);
        CHECK_EQUAL(pending_batch.remote_version, 3);
        CHECK(pending_batch.progress);

        auto validate_changeset = [&](size_t idx, version_type rv, version_type lv, char val, timestamp_type ts,
                                      file_ident_type ident) {
            auto& changeset = pending_batch.changesets[idx];
            CHECK_EQUAL(changeset.remote_version, rv);
            CHECK_EQUAL(changeset.last_integrated_local_version, lv);
            CHECK_EQUAL(changeset.origin_timestamp, ts);
            CHECK_EQUAL(changeset.origin_file_ident, ident);
            CHECK_EQUAL(changeset.original_changeset_size, 1024);
            util::Span<const char> data(changeset.data.get_first_chunk().data(),
                                        changeset.data.get_first_chunk().size());
            CHECK(std::all_of(data.begin(), data.end(), [&](char ch) {
                return ch == val;
            }));
        };

        validate_changeset(0, 3, 6, 'a', 1, 1);
        validate_changeset(1, 3, 7, 'b', 2, 1);
        validate_changeset(2, 3, 8, 'c', 3, 1);

        auto tr = db->start_write();
        store.pop_front_pending(tr, pending_batch.changesets.size());
        tr->commit();
        CHECK(store.has_pending());

        pending_batch = store.peek_pending(1024 * 2);
        CHECK_EQUAL(pending_batch.changesets.size(), 2);
        CHECK_EQUAL(pending_batch.remaining_changesets, 0);
        CHECK_EQUAL(pending_batch.query_version, 1);
        CHECK_EQUAL(pending_batch.remote_version, 3);
        CHECK(pending_batch.progress);
        validate_changeset(0, 3, 9, 'd', 4, 2);
        validate_changeset(1, 3, 10, 'e', 5, 3);

        tr = db->start_write();
        store.pop_front_pending(tr, pending_batch.changesets.size());
        tr->commit();
        CHECK_NOT(store.has_pending());
        CHECK_NOT(store.query_version());
        CHECK_NOT(store.remote_version());
    }
}

TEST(Sync_PendingBootstrapStoreClear)
{
    SHARED_GROUP_TEST_PATH(db_path);
    SyncProgress progress;
    progress.download = {5, 5};
    progress.latest_server_version = {5, 123456789};
    progress.upload = {5, 5};
    auto db = DB::create(make_client_replication(), db_path);
    sync::PendingBootstrapStore store(db, *test_context.logger);

    CHECK_NOT(store.has_pending());
    std::vector<RemoteChangeset> changesets;
    std::vector<std::string> changeset_data;

    changeset_data.emplace_back(1024, 'a');
    changesets.emplace_back(5, 6, BinaryData(changeset_data.back()), 1, 1);
    changesets.back().original_changeset_size = 1024;
    changeset_data.emplace_back(1024, 'b');
    changesets.emplace_back(5, 7, BinaryData(changeset_data.back()), 2, 1);
    changesets.back().original_changeset_size = 1024;

    bool created_new_batch = false;
    store.add_batch(2, 5, progress, changesets, &created_new_batch);
    CHECK(created_new_batch);
    CHECK(store.has_pending());
    CHECK(store.query_version());
    CHECK(store.remote_version());
    CHECK_EQUAL(*store.query_version(), 2);
    CHECK_EQUAL(*store.remote_version(), 5);

    auto pending_batch = store.peek_pending(1025);
    CHECK_EQUAL(pending_batch.changesets.size(), 2);
    CHECK_EQUAL(pending_batch.remaining_changesets, 0);
    CHECK_EQUAL(pending_batch.query_version, 2);
    CHECK_EQUAL(pending_batch.remote_version, 5);
    CHECK(pending_batch.progress);

    store.clear();
    CHECK_NOT(store.has_pending());
    CHECK_NOT(store.query_version());
    CHECK_NOT(store.remote_version());

    pending_batch = store.peek_pending(1024);
    CHECK_EQUAL(pending_batch.changesets.size(), 0);
    CHECK_EQUAL(pending_batch.query_version, 0);
    CHECK_EQUAL(pending_batch.remaining_changesets, 0);
    CHECK_NOT(pending_batch.progress);
}

TEST(Sync_PendingBootstrapStoreRestart)
{
    SHARED_GROUP_TEST_PATH(db_path);
    std::vector<std::string> changeset_data;
    int last_count = 0;
    auto db = DB::create(make_client_replication(), db_path);
    sync::PendingBootstrapStore store(db, *test_context.logger);

    auto create_changesets = [&changeset_data, &last_count](int64_t remote_version, int count) {
        std::vector<RemoteChangeset> changesets;
        while (count-- > 0) {
            changeset_data.emplace_back(1024, (char)('a' + last_count));
            changesets.emplace_back(remote_version, 5 + last_count, BinaryData(changeset_data.back()), last_count, 1);
            changesets.back().original_changeset_size = 1024;
            ++last_count;
        }
        return changesets;
    };

    auto verify_store_state = [&](sync::PendingBootstrapStore& store, bool pending, int64_t query_version,
                                  int64_t remote_version, int count) {
        CHECK_EQUAL(store.has_pending(), pending);
        CHECK_EQUAL(*store.query_version(), query_version);
        CHECK_EQUAL(*store.remote_version(), remote_version);
        auto stats = store.pending_stats();
        CHECK_EQUAL(stats.pending_changesets, count);
        CHECK_EQUAL(stats.query_version, query_version);
        CHECK_EQUAL(stats.remote_version, remote_version);
        CHECK_EQUAL(stats.pending_changeset_bytes, 1024 * count);
    };

    CHECK_NOT(store.has_pending());
    CHECK_NOT(store.query_version());
    CHECK_NOT(store.remote_version());

    auto changesets = create_changesets(4, 4);
    bool new_entry = false;
    // Add an initial set of 4 changesets with versions: query 3 / remote 4
    store.add_batch(3, 4, std::nullopt, changesets, &new_entry);
    CHECK(new_entry);
    verify_store_state(store, false, 3, 4, 4);

    changesets = create_changesets(4, 3);
    new_entry = false;
    // Add an initial set of 3 changesets with versions: query 4 / remote 4
    store.add_batch(4, 4, std::nullopt, changesets, &new_entry);
    CHECK(new_entry);
    // Should restart the bootstrap entry with 3 changesets
    verify_store_state(store, false, 4, 4, 3);

    changesets = create_changesets(6, 5);
    new_entry = false;
    // Add an initial set of 5 changesets with versions: query 4 / remote 6
    store.add_batch(4, 6, std::nullopt, changesets, &new_entry);
    CHECK(new_entry);
    // Should restart the bootstrap entry with 5 changesets
    verify_store_state(store, false, 4, 6, 5);

    SyncProgress progress;
    progress.download = {6, 5};
    progress.latest_server_version = {5, 123456789};
    progress.upload = {5, 5};

    changesets = create_changesets(6, 2);
    new_entry = false;
    // Add an second set of 2 changesets with progress and versions: query 4 / remote 6
    store.add_batch(4, 6, progress, changesets, &new_entry);
    CHECK_NOT(new_entry);
    // Should add to the current bootstrap entry with 7 changesets
    verify_store_state(store, true, 4, 6, 7);

    changesets = create_changesets(6, 1);
    new_entry = false;
    // Add an new set of 1 changeset with versions: query 4 / remote 6
    store.add_batch(4, 6, std::nullopt, changesets, &new_entry);
    CHECK(new_entry);
    // Should restart the bootstrap entry with 1 changeset
    verify_store_state(store, false, 4, 6, 1);
}

} // namespace realm::sync

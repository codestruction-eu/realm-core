////////////////////////////////////////////////////////////////////////////
//
// Copyright 2017 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#include <realm/object-store/sync/sync_session.hpp>

#include <realm/util/scope_exit.hpp>

#if REALM_ENABLE_AUTH_TESTS
#include "util/test_file.hpp"
#include "util/sync/flx_sync_harness.hpp"
#include "util/sync/sync_test_utils.hpp"

#include <realm/object-store/impl/object_accessor_impl.hpp>
#include <realm/object-store/sync/async_open_task.hpp>
#include <realm/object-store/util/scheduler.hpp>

using namespace realm::app;
#endif

#include <catch2/catch_all.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>
using namespace Catch::Matchers;

using namespace realm;

using NotifierType = SyncSession::ProgressDirection;

struct TestSyncProgressNotifier : _impl::SyncProgressNotifier {
    void update(uint64_t downloaded, uint64_t downloadable, uint64_t uploaded, uint64_t uploadable,
                uint64_t snapshot_version)
    {
        bool download_is_completed = downloaded >= downloadable;
        double download_estimate =
            !download_is_completed && downloadable > 0 ? (downloaded / double(downloadable)) : 1.0;
        bool upload_is_completed = uploaded >= uploadable;
        double upload_estimate = !upload_is_completed && uploadable > 0 ? (uploaded / double(uploadable)) : 1.0;
        using Base = _impl::SyncProgressNotifier;
        Base::update(NotifierType::download, snapshot_version, downloaded, downloadable, download_estimate,
                     download_is_completed);
        Base::update(NotifierType::upload, snapshot_version, uploaded, uploadable, upload_estimate,
                     upload_is_completed);
    }
};

TEST_CASE("progress notification", "[sync][session][progress]") {
    TestSyncProgressNotifier progress;
    uint64_t transferred = 0;
    uint64_t transferrable = 0;
    double progress_estimate = 0;
    bool callback_was_called = false;

    auto default_callback = [&](uint64_t xferred, uint64_t xferable, double p) {
        transferred = xferred;
        transferrable = xferable;
        progress_estimate = p;
        callback_was_called = true;
    };

    auto register_default_callback = [&](NotifierType type, bool is_streaming = false) {
        return progress.register_callback(default_callback, type, is_streaming);
    };
    auto register_default_upload_callback = [&](bool is_streaming = false) {
        return register_default_callback(NotifierType::upload, is_streaming);
    };
    auto register_default_download_callback = [&](bool is_streaming = false) {
        return register_default_callback(NotifierType::download, is_streaming);
    };

    SECTION("callback is not called prior to first update") {
        register_default_upload_callback();
        register_default_download_callback();
        REQUIRE_FALSE(callback_was_called);
    }

    SECTION("callback is invoked immediately when a progress update has already occurred") {
        progress.set_local_version(1);
        progress.update(0, 0, 0, 0, 1);

        SECTION("for upload notifications, with no data transfer ongoing") {
            REQUIRE_FALSE(callback_was_called);
            register_default_upload_callback();
            REQUIRE(callback_was_called);
        }

        SECTION("for download notifications, with no data transfer ongoing") {
            REQUIRE_FALSE(callback_was_called);
            register_default_download_callback();
            REQUIRE(callback_was_called);
        }

        SECTION("can register another notifier while in the initial notification without deadlock") {
            int counter = 0;
            progress.register_callback(
                [&](auto, auto, auto) {
                    counter++;
                    progress.register_callback(
                        [&](auto, auto, auto) {
                            counter++;
                        },
                        NotifierType::upload, false);
                },
                NotifierType::download, false);
            REQUIRE(counter == 2);
        }
    }

    SECTION("callback is invoked after each update for streaming notifiers") {
        progress.update(0, 0, 0, 0, 1);

        uint64_t current_transferred = 0;
        uint64_t current_transferrable = 0;

        SECTION("for upload notifications") {
            register_default_upload_callback(true);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 60;
            current_transferrable = 912;
            progress.update(25, 26, current_transferred, current_transferrable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Second callback
            callback_was_called = false;
            current_transferred = 79;
            current_transferrable = 1021;
            progress.update(68, 191, current_transferred, current_transferrable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Third callback
            callback_was_called = false;
            current_transferred = 150;
            current_transferrable = 1228;
            progress.update(199, 591, current_transferred, current_transferrable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
        }

        SECTION("for download notifications") {
            register_default_download_callback(true);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 60;
            current_transferrable = 912;
            progress.update(current_transferred, current_transferrable, 25, 26, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Second callback
            callback_was_called = false;
            current_transferred = 79;
            current_transferrable = 1021;
            progress.update(current_transferred, current_transferrable, 68, 191, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Third callback
            callback_was_called = false;
            current_transferred = 150;
            current_transferrable = 1228;
            progress.update(current_transferred, current_transferrable, 199, 591, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
        }

        SECTION("token unregistration works") {
            uint64_t token = register_default_download_callback(true);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 60;
            current_transferrable = 912;
            progress.update(current_transferred, current_transferrable, 25, 26, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Unregister
            progress.unregister_callback(token);

            // Second callback: should not actually do anything.
            callback_was_called = false;
            current_transferred = 150;
            current_transferrable = 1228;
            progress.update(current_transferred, current_transferrable, 199, 591, 1);
            CHECK(!callback_was_called);
        }

        SECTION("for multiple notifiers") {
            register_default_download_callback(true);
            REQUIRE(callback_was_called);

            // Register a second notifier.
            bool callback_was_called_2 = false;
            uint64_t transferred_2 = 0;
            uint64_t transferrable_2 = 0;
            double progress_estimate_2 = 0;
            progress.register_callback(
                [&](auto xferred, auto xferable, auto p) {
                    transferred_2 = xferred;
                    transferrable_2 = xferable;
                    progress_estimate_2 = p;
                    callback_was_called_2 = true;
                },
                NotifierType::upload, true);
            REQUIRE(callback_was_called_2);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            callback_was_called_2 = false;
            uint64_t current_uploaded = 16;
            uint64_t current_uploadable = 201;
            uint64_t current_downloaded = 68;
            uint64_t current_downloadable = 182;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == current_downloadable);
            CHECK(callback_was_called_2);
            CHECK(transferred_2 == current_uploaded);
            CHECK(transferrable_2 == current_uploadable);

            // Second callback
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 31;
            current_uploadable = 329;
            current_downloaded = 76;
            current_downloadable = 191;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == current_downloadable);
            CHECK(callback_was_called_2);
            CHECK(transferred_2 == current_uploaded);
            CHECK(transferrable_2 == current_uploadable);
        }
    }

    SECTION("properly runs for non-streaming notifiers") {
        uint64_t current_transferred = 0;
        uint64_t current_transferrable = 0;

        SECTION("for upload notifications") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            const uint64_t original_transferrable = current_transferrable;
            progress.update(21, 26, current_transferred, current_transferrable, 1);

            register_default_upload_callback();
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 66;
            current_transferrable = 582;
            progress.update(25, 26, current_transferred, current_transferrable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);

            // Second callback
            callback_was_called = false;
            current_transferred = original_transferrable + 100;
            current_transferrable = 1021;
            progress.update(68, 191, current_transferred, current_transferrable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);

            // The notifier should be unregistered at this point, and not fire.
            callback_was_called = false;
            current_transferred = original_transferrable + 250;
            current_transferrable = 1228;
            progress.update(199, 591, current_transferred, current_transferrable, 1);
            CHECK(!callback_was_called);
        }

        SECTION("upload notifications are not sent until all local changesets have been processed") {
            progress.set_local_version(4);

            register_default_upload_callback();
            REQUIRE_FALSE(callback_was_called);

            current_transferred = 66;
            current_transferrable = 582;
            progress.update(0, 0, current_transferred, current_transferrable, 3);
            REQUIRE_FALSE(callback_was_called);

            current_transferred = 77;
            current_transferrable = 1021;
            progress.update(0, 0, current_transferred, current_transferrable, 4);
            REQUIRE(callback_was_called);
            CHECK(transferred == current_transferred);
            // should not have captured transferrable from the first update
            CHECK(transferrable == current_transferrable);
        }

        SECTION("for download notifications") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            const uint64_t original_transferrable = current_transferrable;
            progress.update(current_transferred, current_transferrable, 21, 26, 1);

            register_default_download_callback();
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 66;
            current_transferrable = 582;
            progress.update(current_transferred, current_transferrable, 25, 26, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);

            // Second callback
            callback_was_called = false;
            current_transferred = original_transferrable + 100;
            current_transferrable = 1021;
            progress.update(current_transferred, current_transferrable, 68, 191, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);

            // The notifier should be unregistered at this point, and not fire.
            callback_was_called = false;
            current_transferred = original_transferrable + 250;
            current_transferrable = 1228;
            progress.update(current_transferred, current_transferrable, 199, 591, 1);
            CHECK(!callback_was_called);
        }

        SECTION("download notifications are not sent until a DOWNLOAD message has been received") {
            register_default_download_callback();

            current_transferred = 100;
            current_transferrable = 100;

            // Next we get a DOWNLOAD message telling us there's more to download
            progress.update(current_transferred, current_transferrable, 0, 0, 1);
            REQUIRE(callback_was_called);
            REQUIRE(current_transferrable == transferrable);
            REQUIRE(current_transferred == transferred);

            current_transferred = 200;
            progress.update(current_transferred, current_transferrable, 0, 0, 1);

            // After the download has completed, new notifications complete immediately
            transferred = 0;
            transferrable = 0;
            callback_was_called = false;

            register_default_download_callback();

            REQUIRE(callback_was_called);
            REQUIRE(current_transferrable == transferrable);
            REQUIRE(current_transferred == transferred);
        }

        SECTION("token unregistration works") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            const uint64_t original_transferrable = current_transferrable;
            progress.update(21, 26, current_transferred, current_transferrable, 1);

            uint64_t token = register_default_upload_callback();
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 66;
            current_transferrable = 912;
            progress.update(25, 26, current_transferred, current_transferrable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);

            // Unregister
            progress.unregister_callback(token);

            // Second callback: should not actually do anything.
            callback_was_called = false;
            current_transferred = 67;
            current_transferrable = 1228;
            progress.update(199, 591, current_transferred, current_transferrable, 1);
            CHECK(!callback_was_called);
        }

        SECTION("for multiple notifiers, different directions") {
            // Prime the progress updater
            uint64_t current_uploaded = 16;
            uint64_t current_uploadable = 201;
            uint64_t current_downloaded = 68;
            uint64_t current_downloadable = 182;
            const uint64_t original_uploadable = current_uploadable;
            const uint64_t original_downloadable = current_downloadable;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);

            register_default_upload_callback();
            REQUIRE(callback_was_called);

            // Register a second notifier.
            bool callback_was_called_2 = false;
            uint64_t downloaded = 0;
            uint64_t downloadable = 0;
            double download_progress = 0;
            progress.register_callback(
                [&](auto xferred, auto xferable, auto p) {
                    downloaded = xferred;
                    downloadable = xferable;
                    download_progress = p;
                    callback_was_called_2 = true;
                },
                NotifierType::download, false);
            REQUIRE(callback_was_called_2);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 171;
            current_downloadable = 185;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_uploaded);
            CHECK(transferrable == original_uploadable);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable);

            // Second callback, last one for the upload notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 218;
            current_uploadable = 310;
            current_downloaded = 174;
            current_downloadable = 190;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_uploaded);
            CHECK(transferrable == original_uploadable);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable);

            // Third callback, last one for the download notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 218;
            current_uploadable = 310;
            current_downloaded = 182;
            current_downloadable = 196;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(!callback_was_called);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable);

            // Fourth callback, last one for the download notifier
            callback_was_called_2 = false;
            current_uploaded = 220;
            current_uploadable = 410;
            current_downloaded = 192;
            current_downloadable = 591;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(!callback_was_called);
            CHECK(!callback_was_called_2);
        }

        SECTION("for multiple notifiers, same direction") {
            // Prime the progress updater
            uint64_t current_uploaded = 16;
            uint64_t current_uploadable = 201;
            uint64_t current_downloaded = 68;
            uint64_t current_downloadable = 182;
            const uint64_t original_downloadable = current_downloadable;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);

            register_default_download_callback();
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 171;
            current_downloadable = 185;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == original_downloadable);

            // Register a second notifier.
            bool callback_was_called_2 = false;
            uint64_t downloaded = 0;
            uint64_t downloadable = 0;
            double download_progress = 0;
            const uint64_t original_downloadable_2 = current_downloadable;
            progress.register_callback(
                [&](auto xferred, auto xferable, auto p) {
                    downloaded = xferred;
                    downloadable = xferable;
                    download_progress = p;
                    callback_was_called_2 = true;
                },
                NotifierType::download, false);
            // Wait for the initial callback.
            REQUIRE(callback_was_called_2);

            // Second callback, last one for first notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 182;
            current_downloadable = 190;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == original_downloadable);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable_2);

            // Third callback, last one for second notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 189;
            current_downloadable = 250;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(!callback_was_called);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable_2);

            // Fourth callback
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 201;
            current_downloadable = 289;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1);
            CHECK(!callback_was_called_2);
        }

        SECTION("download notifiers handle transferrable decreasing") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            const uint64_t original_transferrable = current_transferrable;
            progress.update(current_transferred, current_transferrable, 21, 26, 1);

            register_default_download_callback();
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Download some data but also drop the total. transferrable should
            // update because it decreased.
            callback_was_called = false;
            current_transferred = 160;
            current_transferrable = 451;
            progress.update(current_transferred, current_transferrable, 25, 26, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Increasing current_transferrable should not increase transferrable
            const uint64_t previous_transferrable = current_transferrable;
            callback_was_called = false;
            current_transferrable = 1000;
            progress.update(current_transferred, current_transferrable, 68, 191, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == previous_transferrable);

            // Transferrable dropping to be equal to transferred should notify
            // and then expire the notifier
            callback_was_called = false;
            current_transferred = 200;
            current_transferrable = current_transferred;
            progress.update(current_transferred, current_transferrable, 191, 192, 1);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferred);

            // The notifier should be unregistered at this point, and not fire.
            callback_was_called = false;
            current_transferred = original_transferrable + 250;
            current_transferrable = 1228;
            progress.update(current_transferred, current_transferrable, 199, 591, 1);
            CHECK(!callback_was_called);
        }
    }
}

#if REALM_ENABLE_AUTH_TESTS

struct TestSetup {
    TableRef get_table(const SharedRealm& r)
    {
        return r->read_group().get_table("class_" + table_name);
    }

    size_t add_objects(SharedRealm& r, int num = 5)
    {
        CppContext ctx(r);
        for (int i = 0; i < num; ++i) {
            // use specifically separate transactions for a bit of history
            r->begin_transaction();
            Object::create(ctx, r, StringData(table_name), std::any(make_one(i)));
            r->commit_transaction();
        }
        return get_table(r)->size();
    }

    virtual SyncTestFile make_config() = 0;
    virtual AnyDict make_one(int64_t idx) = 0;

    std::string table_name;
};

struct PBS : TestSetup {
    PBS()
    {
        table_name = "Dog";
    }

    SyncTestFile make_config() override
    {
        const auto schema = get_default_schema();
        return SyncTestFile(session.app(), partition, schema);
    }

    AnyDict make_one(int64_t /* idx */) override
    {
        return AnyDict{{"_id", std::any(ObjectId::gen())},
                       {"breed", std::string("bulldog")},
                       {"name", random_string(1024 * 1024)}};
    }

    TestAppSession session;
    const std::string partition = random_string(100);
};

struct FLX : TestSetup {
    FLX(const std::string& app_id = "flx_sync_progress")
        : harness(app_id)
    {
        table_name = (*harness.schema().begin()).name;
    }

    SyncTestFile make_config() override
    {
        auto config = harness.make_test_file();
        add_subscription(*config.sync_config);
        return config;
    }

    void add_subscription(SyncConfig& config)
    {
        config.rerun_init_subscription_on_open = true;
        config.subscription_initializer = [&](SharedRealm&& realm) {
            add_subscription(realm);
        };
    }

    void add_subscription(SharedRealm& realm)
    {
        auto sub = realm->get_latest_subscription_set().make_mutable_copy();
        sub.insert_or_assign(Query(get_table(realm)));
        sub.commit();
    }

    AnyDict make_one(int64_t idx) override
    {
        return AnyDict{{"_id", ObjectId::gen()},
                       {"queryable_int_field", idx},
                       {"queryable_str_field", random_string(1024 * 1024)}};
    }

    FLXSyncTestHarness harness;
};

/*
 * This test runs a few scenarios for synchronizing changes between two separate realm files for the same app,
 * and verifies high-level consistency in reported progress notification's values.
 *
 * It doesn't try to check for particular reported values: these are checked in sync impl tests,
 * and specific combinations of updates verified directly in SyncProgressNotifier tests.
 *
 * First, test adds a few objects into one realm, verifies that the progress is reported until upload completion.
 * Then it checks how this exact changes are downloaded into the second realm file (this essentially checks
 * how progress is reported with bootstrap store for flx).
 *
 * Next subtests, are here to check how continuous sync reports progress. It reuses the same two realm files
 * with synchronized objects in them both. Test adds more objects into the second realm to sync more changes
 * the other way around: from second realm to the first one, and check if also upload progress correct for
 * the second realm, and download progress for the first realm after its initial upload.
 *  - first by reusing the same realm instance for the second realm
 *  - second by closing and reopening second realm file with new SharedRealm instance
 *
 * Separately, AsyncOpenTask is checked twice: with initial empty third realm file, and with subsequent second opening
 * with more changes to download from the server. The progress reported through task interface should behave in the
 * same way as with cases tested above.
 */
TEMPLATE_TEST_CASE("sync progress notifications", "[sync][baas][progress]", PBS, FLX)
{
    TestType setup;
    constexpr bool is_flx = std::is_same_v<FLX, TestType>;
    size_t expected_count = 0;

#define VERIFY_REALM(realm_1, realm_2, expected)                                                                     \
    {                                                                                                                \
        REQUIRE(expected > 0);                                                                                       \
        REQUIRE(realm_1);                                                                                            \
        REQUIRE(realm_2);                                                                                            \
        REQUIRE(realm_1 != realm_2);                                                                                 \
        auto table1 = setup.get_table(realm_1);                                                                      \
        auto table2 = setup.get_table(realm_2);                                                                      \
        REQUIRE(table1);                                                                                             \
        REQUIRE(table2);                                                                                             \
        REQUIRE(table1->size() == expected);                                                                         \
        REQUIRE(table2->size() == expected);                                                                         \
    }

    struct Progress {
        uint64_t xferred, xferable;
        double estimate;
    };
    typedef std::vector<std::vector<Progress>> ReportedProgress;
    std::mutex progress_mutex;

    // register set of 4 callbacks to put values in predefined places in reported progress list:
    // idx 0: non-streaming/download, 1: non-streaming/upload, 2: streaming/download, 3: streaming/upload
    auto add_callbacks = [&](SharedRealm& realm, ReportedProgress& progress) {
        std::lock_guard lock(progress_mutex);
        size_t idx = progress.size();
        progress.resize(idx + 4);
        for (auto&& stream : {false, true})
            for (auto&& direction : {NotifierType::download, NotifierType::upload})
                realm->sync_session()->register_progress_notifier(
                    [&, i = idx++](uint64_t xferred, uint64_t xferable, double estimate) {
                        progress[i].emplace_back(Progress{xferred, xferable, estimate});
                    },
                    direction, stream);
    };

    auto dump = [](const ReportedProgress& progress, size_t begin = 0, size_t end = -1) {
        std::ostringstream out;
        for (size_t i = begin, e = std::min(end, progress.size()); i < e; ++i) {
            out << (i > begin ? "\n" : "") << i << " [" << progress[i].size() << "]: ";
            for (auto&& p : progress[i])
                out << "(" << p.xferred << ", " << p.xferable << ", " << std::setprecision(4) << p.estimate << "), ";
        }
        return out.str();
    };

    auto clear = [&](ReportedProgress& progress) {
        std::lock_guard lock(progress_mutex);
        for (auto&& values : progress)
            values.clear();
    };

#define VERIFY_PROGRESS_EMPTY(progress, begin, end)                                                                  \
    {                                                                                                                \
        std::lock_guard lock(progress_mutex);                                                                        \
        for (size_t i = begin; i < end; ++i) {                                                                       \
            INFO(util::format("i = %1, %2", i, dump(progress, i, i + 1)));                                           \
            auto&& values = progress[i];                                                                             \
            CHECK(values.size() == 0);                                                                               \
        }                                                                                                            \
    }

#define VERIFY_PROGRESS_CONSISTENCY_ONE(progress, i, expected_download_stages, is_download, is_streaming)            \
    {                                                                                                                \
        INFO(i);                                                                                                     \
        REQUIRE(expected_download_stages > 0);                                                                       \
        REQUIRE(i < progress.size());                                                                                \
        auto&& values = progress[i];                                                                                 \
                                                                                                                     \
        REQUIRE(values.size() > 0);                                                                                  \
        int progress_stages = expected_download_stages;                                                              \
                                                                                                                     \
        for (size_t j = 0; j < values.size(); ++j) {                                                                 \
            auto&& p = values[j];                                                                                    \
            INFO(util::format("Fail index i: %1, j: %2 | Reported progress:\n%3", i, j, dump(progress)));            \
                                                                                                                     \
            CHECK(0 <= p.xferred);                                                                                   \
            CHECK(p.xferred <= p.xferable);                                                                          \
            CHECK(0 <= p.estimate);                                                                                  \
            CHECK(p.estimate <= 1.0);                                                                                \
                                                                                                                     \
            if (j <= 0)                                                                                              \
                continue;                                                                                            \
                                                                                                                     \
            auto&& prev = values[j - 1];                                                                             \
            CHECK(prev.xferred <= p.xferred);                                                                        \
                                                                                                                     \
            /* downloadable may fluctuate by design:                                                                 \
             *   pbs: downloadable from the DOWNLOAD message is added to downloaded so far                           \
             *     always after the changeset integration, commit is always a bit smaller,                           \
             *     hence downloadable always gets a bit smaller than previous value                                  \
             *   flx: downloadable is always as good as an estimate from the server, fluctuates both ways */         \
            if (!is_download)                                                                                        \
                CHECK(prev.xferable <= p.xferable);                                                                  \
                                                                                                                     \
            if (is_download && is_streaming && prev.estimate > p.estimate) {                                         \
                CHECK(prev.estimate == 1.0);                                                                         \
                CHECK(progress_stages >= 1);                                                                         \
                --progress_stages;                                                                                   \
            }                                                                                                        \
            else {                                                                                                   \
                CHECK(prev.estimate <= p.estimate);                                                                  \
            }                                                                                                        \
        }                                                                                                            \
        /* FIXME with non-streaming download last estimate isn't necessarily 1.0                                     \
         *       notification is emitted immediately upon registration and for download the state of remaining       \
         *       changesets for get is not known before first DOWNLOAD message, so until first update happened       \
         *       xferred == xferable and that concludes notifier calls for this callback immediately                 \
         *       see #7452 for details for how this could be solved sensibly */                                      \
        if (!(is_download && !is_streaming && values.size() <= 1)) {                                                 \
            auto&& last = values.back();                                                                             \
            CHECK(last.estimate == 1.0);                                                                             \
            CHECK(last.xferred == last.xferable);                                                                    \
        }                                                                                                            \
    }

#define VERIFY_PROGRESS_CONSISTENCY_EX(progress, begin, end, expected_download_stages)                               \
    {                                                                                                                \
        REQUIRE(begin < end);                                                                                        \
        REQUIRE(end <= progress.size());                                                                             \
                                                                                                                     \
        std::lock_guard lock(progress_mutex);                                                                        \
        for (size_t i = begin; i < end; ++i) {                                                                       \
            /* from add_callbacks: odd sequence number: upload, even: download */                                    \
            bool is_download = i % 2 == 0;                                                                           \
            /* first two lists are for non-streaming, next streaming callbacks */                                    \
            bool is_streaming = i % 4 >= 1;                                                                          \
            VERIFY_PROGRESS_CONSISTENCY_ONE(progress, i, expected_download_stages, is_download, is_streaming);       \
        }                                                                                                            \
    }

#define VERIFY_PROGRESS_CONSISTENCY(progress, begin, end) VERIFY_PROGRESS_CONSISTENCY_EX(progress, begin, end, 1)

    auto wait_for_sync = [](SharedRealm& realm) {
        realm->sync_session()->resume();
        wait_for_upload(*realm);
        wait_for_download(*realm);
        realm->sync_session()->pause();
        realm->refresh();
    };

    auto config_1 = setup.make_config();
    auto realm_1 = Realm::get_shared_realm(config_1);
    realm_1->sync_session()->pause();

    expected_count = setup.add_objects(realm_1);
    ReportedProgress progress_1;
    add_callbacks(realm_1, progress_1);

    wait_for_sync(realm_1);
    VERIFY_PROGRESS_CONSISTENCY(progress_1, 0, 4);
    clear(progress_1);

    SECTION("progress from second realm") {
        auto config2 = setup.make_config();
        auto realm_2 = Realm::get_shared_realm(config2);

        ReportedProgress progress_2;
        add_callbacks(realm_2, progress_2);
        wait_for_sync(realm_2);
        VERIFY_REALM(realm_1, realm_2, expected_count);

        int expected_download_stages = is_flx ? 2 : 1; // + query version 0 progress
        VERIFY_PROGRESS_CONSISTENCY_EX(progress_2, 0, 4, expected_download_stages);
        clear(progress_2);

        VERIFY_PROGRESS_EMPTY(progress_1, 0, progress_1.size());

        SECTION("continuous sync with existing instances") {
            expected_count = setup.add_objects(realm_2);
            add_callbacks(realm_2, progress_2);
            wait_for_sync(realm_2);

            add_callbacks(realm_1, progress_1);
            wait_for_sync(realm_1);
            VERIFY_REALM(realm_1, realm_2, expected_count);

            // initially registered non-streaming callbacks should stay empty
            VERIFY_PROGRESS_EMPTY(progress_1, 0, 2);
            VERIFY_PROGRESS_EMPTY(progress_2, 0, 2);
            // old streaming and newly registered should be reported
            VERIFY_PROGRESS_CONSISTENCY(progress_1, 2, 8);
            VERIFY_PROGRESS_CONSISTENCY(progress_2, 2, 8);
        }

        SECTION("reopen and sync existing realm") {
            realm_2.reset();
            expected_count = setup.add_objects(realm_1);
            wait_for_sync(realm_1);

            realm_2 = Realm::get_shared_realm(config2);
            add_callbacks(realm_2, progress_2);
            wait_for_sync(realm_2);
            VERIFY_REALM(realm_1, realm_2, expected_count);

            VERIFY_PROGRESS_EMPTY(progress_1, 0, 2);
            VERIFY_PROGRESS_CONSISTENCY(progress_1, 2, 4);
            VERIFY_PROGRESS_EMPTY(progress_2, 0, 4);
            VERIFY_PROGRESS_CONSISTENCY(progress_2, 4, 8);
        }

        clear(progress_1);
        clear(progress_2);
    }

    SECTION("progress through async open task on a new realm") {
        auto config_3 = setup.make_config();
        ReportedProgress progress;

        // FIXME hits no_sessions assert in SyncManager due to issue with libuv scheduler and notifications
        config_3.scheduler = util::Scheduler::make_dummy();
        config_3.automatic_change_notifications = false;

        // 0: open and sync fresh realm - should be equal to the realm_1
        // 1: add more objects to sync through realm_1 and try async open again
        for (int i = 0; i < 2; ++i) {
            auto task = Realm::get_synchronized_realm(config_3);
            REQUIRE(task);

            auto progress_index = progress.size();
            progress.resize(progress.size() + 1);

            task->register_download_progress_notifier([&](uint64_t xferred, uint64_t xferable, double estimate) {
                std::lock_guard lock(progress_mutex);
                progress[progress_index].emplace_back(Progress{xferred, xferable, estimate});
            });

            std::atomic<bool> finished = false;
            ThreadSafeReference ref;
            std::exception_ptr err = nullptr;
            task->start([&](ThreadSafeReference r, std::exception_ptr e) {
                ref = std::move(r);
                err = e;
                finished = true;
            });

            util::EventLoop::main().run_until([&] {
                return finished.load();
            });

            CHECK_FALSE(err);
            REQUIRE(ref);
            auto realm_3 = Realm::get_shared_realm(std::move(ref), util::Scheduler::make_dummy());
            VERIFY_REALM(realm_1, realm_3, expected_count);
            realm_3.reset();

            VERIFY_PROGRESS_CONSISTENCY_ONE(progress, progress_index, 1, true, false);
            VERIFY_PROGRESS_EMPTY(progress, 0, progress_index); // previous (from i = 0) should be empty
            clear(progress);

            // add more objects through realm_1 and reopen existing realm on second iteration
            if (i == 0) {
                expected_count = setup.add_objects(realm_1);
                add_callbacks(realm_1, progress_1);
                wait_for_sync(realm_1);
                VERIFY_PROGRESS_EMPTY(progress_1, 0, 2);
                VERIFY_PROGRESS_CONSISTENCY(progress_1, 2, 8);
                clear(progress_1);
            }
        }
    }
}
#endif

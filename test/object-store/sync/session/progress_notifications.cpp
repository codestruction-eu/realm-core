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

TEST_CASE("progress notification", "[sync][session][progress]") {
    _impl::SyncProgressNotifier progress;
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
        harness.do_with_new_user([](std::shared_ptr<SyncUser>&&) {});
    }

    SyncTestFile make_config() override
    {
        auto config = harness.make_test_file();
        config.sync_config->rerun_init_subscription_on_open = true;
        config.sync_config->subscription_initializer = [&](SharedRealm&& realm) {
            auto sub = realm->get_latest_subscription_set().make_mutable_copy();
            sub.insert_or_assign(Query(get_table(realm)));
            sub.commit();
        };
        return config;
    }

    AnyDict make_one(int64_t idx) override
    {
        return AnyDict{{"_id", ObjectId::gen()},
                       {"queryable_int_field", idx},
                       {"queryable_str_field", random_string(1024 * 1024)}};
    }

    FLXSyncTestHarness harness;
};

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
    typedef std::vector<std::vector<Progress>> ProgressValues;
    ProgressValues progress;

    std::mutex mutex;
    auto add_callbacks = [&](SharedRealm& realm) {
        std::scoped_lock lock(mutex);
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

    auto dump = [](const ProgressValues& progress, size_t begin = 0, size_t end = -1) {
        std::ostringstream out;
        for (size_t i = begin, e = std::min(end, progress.size()); i < e; ++i) {
            out << (i > begin ? "\n" : "") << progress[i].size() << ": ";
            for (auto&& p : progress[i])
                out << "(" << p.xferred << ", " << p.xferable << ", " << std::setprecision(2) << p.estimate << "), ";
        }
        return out.str();
    };

    auto clear = [&](ProgressValues& progress) {
        std::scoped_lock lock(mutex);
        for (auto&& values : progress)
            values.clear();
    };

#define VERIFY_PROGRESS_EMPTY(progress, begin, end)                                                                  \
    {                                                                                                                \
        std::scoped_lock lock(mutex);                                                                                \
        for (size_t i = begin; i < end; ++i) {                                                                       \
            INFO(util::format("i = %1, %2", i, dump(progress, i, i + 1)));                                           \
            auto&& values = progress[i];                                                                             \
            CHECK(values.size() == 0);                                                                               \
        }                                                                                                            \
    }

#define VERIFY_PROGRESS_EX(progress, begin, end, expect_multiple_stages)                                             \
    {                                                                                                                \
        REQUIRE(begin < end);                                                                                        \
        REQUIRE(end <= progress.size());                                                                             \
                                                                                                                     \
        std::scoped_lock lock(mutex);                                                                                \
        for (size_t i = begin; i < end; ++i) {                                                                       \
            auto&& values = progress[i];                                                                             \
                                                                                                                     \
            INFO(i);                                                                                                 \
            REQUIRE(values.size() > 0);                                                                              \
                                                                                                                     \
            for (size_t j = 0, e = values.size(); j < e; ++j) {                                                      \
                auto&& p = values[j];                                                                                \
                INFO(util::format("i: %1, j: %2\n%3", i, j, dump(progress)));                                        \
                                                                                                                     \
                CHECK(0 <= p.xferred);                                                                               \
                CHECK(p.xferred <= p.xferable);                                                                      \
                CHECK(0 <= p.estimate);                                                                              \
                CHECK(p.estimate <= 1.0);                                                                            \
                                                                                                                     \
                if (j > 0) {                                                                                         \
                    auto&& prev = values[j - 1];                                                                     \
                    CHECK(prev.xferred <= p.xferred);                                                                \
                    /* xferable may fluctuate by design */                                                           \
                    /* FIXME two full downloads by design or bug with flx? */                                        \
                    if (!expect_multiple_stages || !WithinRel(.9999, .0001).match(prev.estimate))                    \
                        CHECK(prev.estimate <= p.estimate);                                                          \
                }                                                                                                    \
            }                                                                                                        \
            /* FIXME with non-streaming last estimate isn't necessarily 1.0, which depends on bytes xfered */        \
            if (values.size() > 1) {                                                                                 \
                auto&& last = values.back();                                                                         \
                CHECK_THAT(last.estimate, WithinRel(.9999, .0001));                                                  \
                CHECK(last.xferred == last.xferable);                                                                \
            }                                                                                                        \
        }                                                                                                            \
    }

#define VERIFY_PROGRESS(progress, begin, end) VERIFY_PROGRESS_EX(progress, begin, end, false)

    auto wait_for_sync = [](SharedRealm& realm) {
        realm->sync_session()->resume();
        wait_for_upload(*realm);
        wait_for_download(*realm);
        realm->sync_session()->pause();
        realm->refresh();
    };

    auto config1 = setup.make_config();
    auto realm_1 = Realm::get_shared_realm(config1);
    if (is_flx) // wait for initial query 0 to sync for cleaner checks
        wait_for_sync(realm_1);
    realm_1->sync_session()->pause();

    expected_count = setup.add_objects(realm_1);
    add_callbacks(realm_1);
    wait_for_sync(realm_1);

    VERIFY_PROGRESS(progress, 0, 3);
    VERIFY_PROGRESS_EX(progress, 3, 4, is_flx); // with flx query 0 emits progress also
    clear(progress);

    auto config2 = setup.make_config();
    auto realm_2 = Realm::get_shared_realm(config2);
    realm_2->sync_session()->pause();
    add_callbacks(realm_2);
    wait_for_sync(realm_2);

    VERIFY_REALM(realm_1, realm_2, expected_count);

    VERIFY_PROGRESS_EMPTY(progress, 0, 4);
    VERIFY_PROGRESS(progress, 4, 6);
    VERIFY_PROGRESS_EX(progress, 6, 8, is_flx); // with flx query 0 emits progress also
    clear(progress);

    expected_count = setup.add_objects(realm_2);
    wait_for_sync(realm_2);
    wait_for_sync(realm_1);
    VERIFY_REALM(realm_1, realm_2, expected_count);

    VERIFY_PROGRESS_EMPTY(progress, 0, 2);
    VERIFY_PROGRESS(progress, 2, 4);
    VERIFY_PROGRESS_EMPTY(progress, 4, 6);
    VERIFY_PROGRESS(progress, 6, 8);
    clear(progress);

    realm_2.reset();
    expected_count = setup.add_objects(realm_1);
    wait_for_sync(realm_1);

    realm_2 = Realm::get_shared_realm(config2);
    realm_2->sync_session()->pause();
    add_callbacks(realm_2);
    wait_for_sync(realm_2);

    VERIFY_REALM(realm_1, realm_2, expected_count);
    VERIFY_PROGRESS_EMPTY(progress, 0, 2);
    VERIFY_PROGRESS(progress, 2, 4);
    VERIFY_PROGRESS_EMPTY(progress, 4, 8);
    VERIFY_PROGRESS(progress, 8, 12);
    clear(progress);

    // check async open task
    auto config3 = setup.make_config();
    // FIXME hits no_sessions assert in SyncManager due to issue with libuv scheduler and notifications
    config3.scheduler = util::Scheduler::make_dummy();
    config3.automatic_change_notifications = false;

    for (int i = 0; i < 2; ++i) {
        auto task = Realm::get_synchronized_realm(config3);
        REQUIRE(task);
        progress.resize(progress.size() + 1);
        task->register_download_progress_notifier([&](uint64_t xferred, uint64_t xferable, double estimate) {
            std::scoped_lock lock(mutex);
            progress.back().emplace_back(Progress{xferred, xferable, estimate});
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

        VERIFY_PROGRESS(progress, progress.size() - 1, progress.size());
        VERIFY_PROGRESS_EMPTY(progress, 0, progress.size() - 1);
        clear(progress);

        if (i == 0) {
            expected_count = setup.add_objects(realm_1);
            wait_for_sync(realm_1);
            clear(progress);
        }
    }
}
#endif

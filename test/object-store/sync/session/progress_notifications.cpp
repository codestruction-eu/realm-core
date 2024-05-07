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

struct ProgressEntry {
    uint64_t transferred = 0;
    uint64_t transferrable = 0;
    double estimate = 0.0;

    inline bool operator==(const ProgressEntry& other) const noexcept
    {
        return transferred == other.transferred && transferrable == other.transferrable && estimate == other.estimate;
    }
};

static std::string estimate_to_string(double est)
{
    std::ostringstream ss;
    ss << std::setprecision(4) << est;
    return ss.str();
}

static std::ostream& operator<<(std::ostream& os, const ProgressEntry& value)
{
    return os << util::format("{ transferred: %1, transferrable: %2, estimate: %3 }", value.transferred,
                              value.transferrable, estimate_to_string(value.estimate));
}


struct WaitableProgress : public util::AtomicRefCountBase {
    WaitableProgress(const std::shared_ptr<util::Logger>& base_logger, std::string context)
        : logger(std::move(context), base_logger)
    {
    }

    std::function<SyncSession::ProgressNotifierCallback> make_cb()
    {
        auto self = util::bind_ptr(this);
        return [self](uint64_t transferred, uint64_t transferrable, double estimate) {
            self->logger.trace("Progress callback called xferred: %1, xferrable: %2, estimate: %3", transferred,
                               transferrable, estimate_to_string(estimate));
            std::lock_guard lk(self->mutex);
            self->entries.push_back(ProgressEntry{transferred, transferrable, estimate});
            self->cv.notify_one();
        };
    }

    bool empty()
    {
        std::lock_guard lk(mutex);
        return entries.empty();
    }

    std::vector<ProgressEntry> wait_for_full_sync()
    {
        std::unique_lock lk(mutex);
        if (!cv.wait_for(lk, std::chrono::seconds(30), [&] {
                return !entries.empty() && entries.back().transferred >= entries.back().transferrable &&
                       entries.back().estimate >= 1.0;
            })) {
            CAPTURE(entries);
            FAIL("Failed while waiting for progress to complete");
            return {};
        }

        std::vector<ProgressEntry> ret;
        std::swap(ret, entries);
        return ret;
    }

    util::PrefixLogger logger;
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<ProgressEntry> entries;
};

struct TestInputValue {
    struct IsRegistration {};
    explicit TestInputValue(IsRegistration)
        : is_registration(true)
    {
    }

    TestInputValue(int64_t query_version, double cur_estimate, uint64_t transferred, uint64_t transferrable)
        : query_version(query_version)
        , cur_estimate(cur_estimate)
        , transferred(transferred)
        , transferrable(transferrable)
    {
    }

    int64_t query_version = 0;
    double cur_estimate = 0;
    uint64_t transferred = 0;
    uint64_t transferrable = 0;
    bool is_registration = false;
};

struct TestValues {
    std::vector<TestInputValue> input_values;
    std::vector<ProgressEntry> expected_values;
    int64_t registered_at_query_version;
};

TEST_CASE("progress notification", "[sync][session][progress]") {
    using NotifierType = SyncSession::ProgressDirection;
    _impl::SyncProgressNotifier progress;

    SECTION("callback is not called prior to first update") {
        bool callback_was_called = false;
        progress.register_callback(
            [&](auto, auto, double) {
                callback_was_called = true;
            },
            NotifierType::upload, false, 0);
        progress.register_callback(
            [&](auto, auto, double) {
                callback_was_called = true;
            },
            NotifierType::download, false, 0);
        REQUIRE_FALSE(callback_was_called);
    }

    SECTION("callback is invoked immediately when a progress update has already occurred") {
        progress.set_local_version(1);
        progress.update(0, 0, 0, 0, 1, 1.0, 1.0, 0);

        bool callback_was_called = false;
        SECTION("for upload notifications, with no data transfer ongoing") {
            progress.register_callback(
                [&](auto, auto, double) {
                    callback_was_called = true;
                },
                NotifierType::upload, false, 0);
            REQUIRE(callback_was_called);
        }

        SECTION("for download notifications, with no data transfer ongoing") {
            progress.register_callback(
                [&](auto, auto, double) {
                    callback_was_called = true;
                },
                NotifierType::download, false, 0);
        }

        SECTION("can register another notifier while in the initial notification without deadlock") {
            int counter = 0;
            progress.register_callback(
                [&](auto, auto, double) {
                    counter++;
                    progress.register_callback(
                        [&](auto, auto, double) {
                            counter++;
                        },
                        NotifierType::upload, false, 0);
                },
                NotifierType::download, false, 0);
            REQUIRE(counter == 2);
        }
    }

    SECTION("callback is invoked after each update for streaming notifiers") {
        progress.update(0, 0, 0, 0, 1, 0, 0, 0);

        bool callback_was_called = false;
        uint64_t transferred = 0;
        uint64_t transferrable = 0;
        uint64_t current_transferred = 0;
        uint64_t current_transferrable = 0;
        double estimate = 0.0;

        SECTION("for upload notifications") {
            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    callback_was_called = true;
                    estimate = ep;
                },
                NotifierType::upload, true, 0);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 60;
            current_transferrable = 912;
            double current_estimate = current_transferred / double(current_transferrable);
            progress.update(25, 26, current_transferred, current_transferrable, 1, 25 / double(26), current_estimate,
                            0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
            CHECK(estimate == current_estimate);

            // Second callback
            callback_was_called = false;
            current_transferred = 79;
            current_transferrable = 1021;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(68, 191, current_transferred, current_transferrable, 1, 68 / double(191),
                            current_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
            CHECK(estimate == current_estimate);

            // Third callback
            callback_was_called = false;
            current_transferred = 150;
            current_transferrable = 1228;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(199, 591, current_transferred, current_transferrable, 1, 199 / double(591),
                            current_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
            CHECK(estimate == current_estimate);
        }

        SECTION("for download notifications") {
            progress.register_callback(
                [&](auto xferred, auto xferable, double pe) {
                    transferred = xferred;
                    transferrable = xferable;
                    estimate = pe;
                    callback_was_called = true;
                },
                NotifierType::download, true, 0);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 60;
            current_transferrable = 912;
            progress.update(current_transferred, current_transferrable, 25, 26, 1,
                            current_transferred / double(current_transferrable), 1.0, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
            CHECK(estimate == current_transferred / double(current_transferrable));

            // Second callback
            callback_was_called = false;
            current_transferred = 79;
            current_transferrable = 1021;
            progress.update(current_transferred, current_transferrable, 68, 191, 1,
                            current_transferred / double(current_transferrable), 1.0, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
            CHECK(estimate == current_transferred / double(current_transferrable));

            // Third callback
            callback_was_called = false;
            current_transferred = 150;
            current_transferrable = 1228;
            progress.update(current_transferred, current_transferrable, 199, 591, 1,
                            current_transferred / double(current_transferrable), 1.0, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
        }

        SECTION("token unregistration works") {
            uint64_t token = progress.register_callback(
                [&](auto xferred, auto xferable, double) {
                    transferred = xferred;
                    transferrable = xferable;
                    callback_was_called = true;
                },
                NotifierType::download, true, 0);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 60;
            current_transferrable = 912;
            double current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 25, 26, 1, current_estimate, 25 / double(26),
                            0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);

            // Unregister
            progress.unregister_callback(token);

            // Second callback: should not actually do anything.
            callback_was_called = false;
            current_transferred = 150;
            current_transferrable = 1228;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 199, 591, 1, current_estimate,
                            199 / double(591), 0);
            CHECK(!callback_was_called);
        }

        SECTION("for multiple notifiers") {
            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::download, true, 0);
            REQUIRE(callback_was_called);

            // Register a second notifier.
            bool callback_was_called_2 = false;
            uint64_t transferred_2 = 0;
            uint64_t transferrable_2 = 0;
            progress.register_callback(
                [&](auto xferred, auto xferable, double) {
                    transferred_2 = xferred;
                    transferrable_2 = xferable;
                    callback_was_called_2 = true;
                },
                NotifierType::upload, true, 0);
            REQUIRE(callback_was_called_2);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            callback_was_called_2 = false;
            uint64_t current_uploaded = 16;
            uint64_t current_uploadable = 201;
            uint64_t current_downloaded = 68;
            uint64_t current_downloadable = 182;
            auto current_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_estimate, 1.0, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == current_downloadable);
            CHECK(estimate == current_estimate);
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
            current_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_estimate, 1.0, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == current_downloadable);
            CHECK(estimate == current_estimate);
            CHECK(callback_was_called_2);
            CHECK(transferred_2 == current_uploaded);
            CHECK(transferrable_2 == current_uploadable);
        }
    }

    SECTION("properly runs for non-streaming notifiers") {
        bool callback_was_called = false;
        uint64_t transferred = 0;
        uint64_t transferrable = 0;
        uint64_t current_transferred = 0;
        uint64_t current_transferrable = 0;
        double upload_estimate = 0;
        double download_estimate = 0;

        SECTION("for upload notifications") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            const uint64_t original_transferrable = current_transferrable;
            double current_estimate = current_transferred / double(current_transferrable);
            progress.update(21, 26, current_transferred, current_transferrable, 1, 21 / double(26), current_estimate,
                            0);

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    upload_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::upload, false, 0);
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 66;
            current_transferrable = 582;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(21, 26, current_transferred, current_transferrable, 1, 21 / double(26), current_estimate,
                            0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);
            CHECK(upload_estimate == current_transferred / double(original_transferrable));

            // Second callback
            callback_was_called = false;
            current_transferred = original_transferrable + 100;
            current_transferrable = 1021;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(68, 191, current_transferred, current_transferrable, 1, 68 / double(191),
                            current_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);
            CHECK(upload_estimate == std::min(1.0, current_transferred / double(original_transferrable)));

            // The notifier should be unregistered at this point, and not fire.
            callback_was_called = false;
            current_transferred = original_transferrable + 250;
            current_transferrable = 1228;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(199, 591, current_transferred, current_transferrable, 1, 199 / double(591),
                            current_estimate, 0);
            CHECK(!callback_was_called);
        }

        SECTION("upload notifications are not sent until all local changesets have been processed") {
            progress.set_local_version(4);

            progress.register_callback(
                [&](auto xferred, auto xferable, double) {
                    transferred = xferred;
                    transferrable = xferable;
                    callback_was_called = true;
                },
                NotifierType::upload, false, 0);
            REQUIRE_FALSE(callback_was_called);

            current_transferred = 66;
            current_transferrable = 582;
            double current_estimate = current_transferred / double(current_transferrable);
            progress.update(0, 0, current_transferred, current_transferrable, 3, 1.0, current_estimate, 0);
            REQUIRE_FALSE(callback_was_called);

            current_transferred = 77;
            current_transferrable = 1021;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(0, 0, current_transferred, current_transferrable, 4, 1.0, current_estimate, 0);
            REQUIRE(callback_was_called);
            CHECK(transferred == current_transferred);
            // should not have captured transferrable from the first update
            CHECK(transferrable == current_transferrable);
            CHECK(current_estimate == current_estimate);
        }

        SECTION("for download notifications") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            double current_estimate = current_transferred / double(current_transferrable);
            const uint64_t original_transferrable = current_transferrable;
            progress.update(current_transferred, current_transferrable, 21, 26, 1, current_estimate, 21 / double(26),
                            0);

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    download_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::download, false, 0);
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 66;
            current_transferrable = 582;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 25, 26, 1, current_estimate, 25 / double(26),
                            0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);
            CHECK(download_estimate == current_estimate);

            // Second callback
            callback_was_called = false;
            current_transferred = original_transferrable + 100;
            current_transferrable = 1021;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 68, 191, 1, current_estimate,
                            68 / double(191), 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);
            CHECK(download_estimate == current_estimate);

            // The notifier should be unregistered at this point, and not fire.
            callback_was_called = false;
            current_transferred = original_transferrable + 250;
            current_transferrable = 1228;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 199, 591, 1, current_estimate,
                            199 / double(591), 0);
            CHECK(!callback_was_called);
        }

// The functionality of this test was moved out of the object-store and into the sync client.
#if 0
        SECTION("download notifications are not sent until a DOWNLOAD message has been received") {
            _impl::SyncProgressNotifier progress;

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    download_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::download, false, 0);

            current_transferred = 100;
            current_transferrable = 100;
            double current_estimate = 1.0;
            // Last time we ran we downloaded everything, so sync will send us an
            // update reporting that
            progress.update(current_transferred, current_transferrable, 0, 0, 1, current_estimate, 1.0, 0);
            REQUIRE_FALSE(callback_was_called);

            current_transferred = 100;
            current_transferrable = 200;
            current_estimate = current_transferred / double(current_transferrable);
            // Next we get a DOWNLOAD message telling us there's more to download
            progress.update(current_transferred, current_transferrable, 0, 0, 1, current_estimate, 1.0, 0);
            REQUIRE(callback_was_called);
            REQUIRE(current_transferrable == transferrable);
            REQUIRE(current_transferred == transferred);
            REQUIRE(current_estimate == download_estimate);

            current_transferred = 200;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 0, 0, 1, current_estimate, 1.0, 0);

            // After the download has completed, new notifications complete immediately
            transferred = 0;
            transferrable = 0;
            callback_was_called = false;

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    download_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::download, false, 0);

            REQUIRE(callback_was_called);
            REQUIRE(current_transferrable == transferrable);
            REQUIRE(current_transferred == transferred);
            REQUIRE(current_estimate == download_estimate);
        }
#endif

        SECTION("token unregistration works") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            double current_estimate = current_transferred / double(current_transferrable);
            const uint64_t original_transferrable = current_transferrable;
            progress.update(21, 26, current_transferred, current_transferrable, 1, 21 / double(26), current_estimate,
                            0);

            uint64_t token = progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    upload_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::upload, false, 0);
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_transferred = 66;
            current_transferrable = 912;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(25, 26, current_transferred, current_transferrable, 1, 25 / double(26), current_estimate,
                            0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == original_transferrable);
            CHECK(upload_estimate == std::min(1.0, current_transferred / double(original_transferrable)));

            // Unregister
            progress.unregister_callback(token);

            // Second callback: should not actually do anything.
            callback_was_called = false;
            current_transferred = 67;
            current_transferrable = 1228;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(199, 591, current_transferred, current_transferrable, 1, 199 / double(591),
                            current_estimate, 0);
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
            double current_upload_estimate = current_uploaded / double(current_uploadable);
            double current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    upload_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::upload, false, 0);
            REQUIRE(callback_was_called);

            // Register a second notifier.
            bool callback_was_called_2 = false;
            uint64_t downloaded = 0;
            uint64_t downloadable = 0;
            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    downloaded = xferred;
                    downloadable = xferable;
                    download_estimate = ep;
                    callback_was_called_2 = true;
                },
                NotifierType::download, false, 0);
            REQUIRE(callback_was_called_2);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 171;
            current_downloadable = 185;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_uploaded);
            CHECK(transferrable == original_uploadable);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable);
            CHECK(upload_estimate == std::min(1.0, current_uploaded / double(original_uploadable)));
            CHECK(download_estimate == current_download_estimate);

            // Second callback, last one for the upload notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 218;
            current_uploadable = 310;
            current_downloaded = 174;
            current_downloadable = 190;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_uploaded);
            CHECK(transferrable == original_uploadable);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable);
            CHECK(upload_estimate == std::min(1.0, current_uploaded / double(original_uploadable)));
            CHECK(download_estimate == current_download_estimate);

            // Third callback, last one for the download notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 218;
            current_uploadable = 310;
            current_downloaded = 182;
            current_downloadable = 196;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(!callback_was_called);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable);
            CHECK(upload_estimate == std::min(1.0, current_uploaded / double(original_uploadable)));
            CHECK(download_estimate == current_download_estimate);

            // Fourth callback, last one for the download notifier
            callback_was_called_2 = false;
            current_uploaded = 220;
            current_uploadable = 410;
            current_downloaded = 192;
            current_downloadable = 591;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(!callback_was_called);
            CHECK(!callback_was_called_2);
        }

        SECTION("for multiple notifiers, same direction") {
            // Prime the progress updater
            uint64_t current_uploaded = 16;
            uint64_t current_uploadable = 201;
            uint64_t current_downloaded = 68;
            uint64_t current_downloadable = 182;
            double current_upload_estimate = current_uploaded / double(current_uploadable);
            double current_download_estimate = current_downloaded / double(current_downloadable);

            const uint64_t original_downloadable = current_downloadable;
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    download_estimate = ep;
                    callback_was_called = true;
                },
                NotifierType::download, false, 0);
            REQUIRE(callback_was_called);

            // Now manually call the notifier handler a few times.
            callback_was_called = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 171;
            current_downloadable = 185;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);

            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == original_downloadable);

            // Register a second notifier.
            bool callback_was_called_2 = false;
            uint64_t downloaded = 0;
            uint64_t downloadable = 0;
            const uint64_t original_downloadable_2 = current_downloadable;
            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    downloaded = xferred;
                    downloadable = xferable;
                    download_estimate = ep;
                    callback_was_called_2 = true;
                },
                NotifierType::download, false, 0);
            // Wait for the initial callback.
            REQUIRE(callback_was_called_2);

            // Second callback, last one for first notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 182;
            current_downloadable = 190;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_downloaded);
            CHECK(transferrable == original_downloadable);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable_2);
            CHECK(download_estimate == current_download_estimate);

            // Third callback, last one for second notifier
            callback_was_called = false;
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 189;
            current_downloadable = 250;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(!callback_was_called);
            CHECK(callback_was_called_2);
            CHECK(downloaded == current_downloaded);
            CHECK(downloadable == original_downloadable_2);
            CHECK(download_estimate == current_download_estimate);

            // Fourth callback
            callback_was_called_2 = false;
            current_uploaded = 36;
            current_uploadable = 310;
            current_downloaded = 201;
            current_downloadable = 289;
            current_upload_estimate = current_uploaded / double(current_uploadable);
            current_download_estimate = current_downloaded / double(current_downloadable);
            progress.update(current_downloaded, current_downloadable, current_uploaded, current_uploadable, 1,
                            current_download_estimate, current_upload_estimate, 0);
            CHECK(!callback_was_called_2);
        }

        SECTION("download notifiers handle transferrable decreasing") {
            // Prime the progress updater
            current_transferred = 60;
            current_transferrable = 501;
            const uint64_t original_transferrable = current_transferrable;
            double current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 21, 26, 1, current_estimate, 21 / double(26),
                            0);

            progress.register_callback(
                [&](auto xferred, auto xferable, double ep) {
                    transferred = xferred;
                    transferrable = xferable;
                    callback_was_called = true;
                    download_estimate = ep;
                },
                NotifierType::download, false, 0);
            // Wait for the initial callback.
            REQUIRE(callback_was_called);

            // Download some data but also drop the total. transferrable should
            // update because it decreased.
            callback_was_called = false;
            current_transferred = 160;
            current_transferrable = 451;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 25, 26, 1, current_estimate, 26 / double(26),
                            0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferrable);
            CHECK(current_estimate == download_estimate);

            // Increasing current_transferrable should not increase transferrable
            const uint64_t previous_transferrable = current_transferrable;
            callback_was_called = false;
            current_transferrable = 1000;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 68, 191, 1, current_estimate,
                            68 / double(191), 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == previous_transferrable);
            CHECK(download_estimate == current_estimate);

            // Transferrable dropping to be equal to transferred should notify
            // and then expire the notifier
            callback_was_called = false;
            current_transferred = 200;
            current_transferrable = current_transferred;
            current_estimate = current_transferred / double(current_transferrable);
            progress.update(current_transferred, current_transferrable, 191, 192, 1, current_estimate,
                            191 / double(192), 0);
            CHECK(callback_was_called);
            CHECK(transferred == current_transferred);
            CHECK(transferrable == current_transferred);
            CHECK(current_estimate == download_estimate);

            // The notifier should be unregistered at this point, and not fire.
            callback_was_called = false;
            current_transferred = original_transferrable + 250;
            current_transferrable = 1228;
            current_estimate = current_transferred / double(current_transferrable);

            progress.update(current_transferred, current_transferrable, 199, 591, 1, current_estimate,
                            199 / double(591), 0);
            CHECK(!callback_was_called);
        }
    }

    SECTION("flx streaming notifiers") {
        // clang-format off
        TestValues test_values = GENERATE(
            // resgisters at the begining and should see all entries.
            TestValues{{
                TestInputValue{TestInputValue::IsRegistration{}},
                TestInputValue{0, 0, 0, 0},
                TestInputValue{0, 1, 200, 200},
                TestInputValue{1, 0.2, 300, 600},
                TestInputValue{1, 0.4, 400, 600},
                TestInputValue{1, 0.8, 600, 700},
                TestInputValue{1, 1, 700, 700},
                TestInputValue{2, 0.3, 800, 1000},
                TestInputValue{2, 0.6, 900, 1000},
                TestInputValue{2, 1, 1000, 1000},
            }, {
                ProgressEntry{0, 0, 0},
                ProgressEntry{200, 200, 1},
                ProgressEntry{300, 600, 0.2},
                ProgressEntry{400, 600, 0.4},
                ProgressEntry{600, 700, 0.8},
                ProgressEntry{700, 700, 1},
                ProgressEntry{800, 1000, 0.3},
                ProgressEntry{900, 1000, 0.6},
                ProgressEntry{1000, 1000, 1},
            }, 1},
            TestValues{{
                TestInputValue{1, 0.2, 300, 600},
                TestInputValue{1, 0.4, 400, 600},
                TestInputValue{TestInputValue::IsRegistration{}},
                TestInputValue{1, 0.8, 600, 700},
                TestInputValue{1, 1, 700, 700},
            }, {
                ProgressEntry{400, 600, 0.4},
                ProgressEntry{600, 700, 0.8},
                ProgressEntry{700, 700, 1.0},
            }, 1},
            // registers for a query version that's already up-to-date - should get an immediate update
            // with a progress estimate of 1 and whatever the current transferred/transferrable numbers are
            TestValues{{
                TestInputValue{2, 0.5, 800, 900},
                TestInputValue{2, 1, 900, 900},
                TestInputValue{TestInputValue::IsRegistration{}},
                TestInputValue{2, 1, 1000, 1000}
            }, {
                ProgressEntry{900, 900, 1},
                ProgressEntry{1000, 1000, 1},
            }, 1}
        );
        // clang-format on

        auto logger = util::Logger::get_default_logger();
        auto progress_output = util::make_bind<WaitableProgress>(logger, "flx non-streaming download");

        uint64_t snapshot = 1;
        for (const auto& input_val : test_values.input_values) {
            if (input_val.is_registration) {
                progress.register_callback(progress_output->make_cb(), NotifierType::download, true,
                                           test_values.registered_at_query_version);
                continue;
            }
            progress.update(input_val.transferred, input_val.transferrable, 0, 0, ++snapshot, input_val.cur_estimate,
                            0.0, input_val.query_version);
        }

        const auto output_values = progress_output->wait_for_full_sync();

        REQUIRE_THAT(output_values, Catch::Matchers::Equals(test_values.expected_values));
    }

    SECTION("flx non-streaming notifiers") {
        // clang-format off
        TestValues test_values = GENERATE(
            // registers for query version 1 on an empty realm - should see the full progression
            // of query version 1 and nothing else.
            TestValues{{
                TestInputValue{TestInputValue::IsRegistration{}},
                TestInputValue{0, 0, 0, 0},
                TestInputValue{0, 1, 200, 200},
                TestInputValue{1, 0.2, 300, 600},
                TestInputValue{1, 0.4, 400, 600},
                TestInputValue{1, 0.8, 600, 700},
                TestInputValue{1, 1, 700, 700},
                TestInputValue{2, 0.3, 800, 1000},
                TestInputValue{2, 0.6, 900, 1000},
                TestInputValue{2, 1, 1000, 1000},
            }, {
                ProgressEntry{300, 600, 0.2},
                ProgressEntry{400, 600, 0.4},
                ProgressEntry{600, 600, 0.8},
                ProgressEntry{700, 600, 1.0},
            }, 1},
            // registers a notifier in the middle of syncing the target query version
            TestValues{{
                TestInputValue{1, 0.2, 300, 600},
                TestInputValue{1, 0.4, 400, 600},
                TestInputValue{TestInputValue::IsRegistration{}},
                TestInputValue{1, 0.8, 600, 700},
                TestInputValue{1, 1, 700, 700},
                // There's also a progress notification for a regular steady state
                // download message that gets ignored because we're already up-to-date
                TestInputValue{1, 1, 800, 800},
            }, {
                ProgressEntry{400, 600, 0.4},
                ProgressEntry{600, 600, 0.8},
                ProgressEntry{700, 600, 1.0},
            }, 1},
            // registers for a notifier for a later query version - should only see notifications
            // for downloads greater than the requested query version
            TestValues{{

                TestInputValue{TestInputValue::IsRegistration{}},
                TestInputValue{1, 0.8, 700, 700},
                TestInputValue{1, 1, 700, 700},
                TestInputValue{3, 0.5, 800, 900},
                TestInputValue{3, 1, 900, 900},
            }, {
                ProgressEntry{800, 900, 0.5},
                ProgressEntry{900, 900, 1},
            }, 2},
            // registers for a query version that's already up-to-date - should get an immediate update
            // with a progress estimate of 1 and whatever the current transferred/transferrable numbers are
            TestValues{{
                TestInputValue{2, 0.5, 800, 900},
                TestInputValue{2, 1, 900, 900},
                TestInputValue{TestInputValue::IsRegistration{}},
            }, {
                ProgressEntry{900, 900, 1},
            }, 1}
        );
        // clang-format on

        auto logger = util::Logger::get_default_logger();
        auto progress_output = util::make_bind<WaitableProgress>(logger, "flx non-streaming download");

        uint64_t snapshot = 1;
        for (const auto& input_val : test_values.input_values) {
            if (input_val.is_registration) {
                progress.register_callback(progress_output->make_cb(), NotifierType::download, false,
                                           test_values.registered_at_query_version);
                continue;
            }
            progress.update(input_val.transferred, input_val.transferrable, 0, 0, ++snapshot, input_val.cur_estimate,
                            0.0, input_val.query_version);
        }

        const auto output_values = progress_output->wait_for_full_sync();

        REQUIRE_THAT(output_values, Catch::Matchers::Equals(test_values.expected_values));
    }
}

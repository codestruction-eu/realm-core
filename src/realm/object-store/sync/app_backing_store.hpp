////////////////////////////////////////////////////////////////////////////
//
// Copyright 2023 Realm Inc.
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

#ifndef REALM_OS_APP_BACKING_STORE_HPP
#define REALM_OS_APP_BACKING_STORE_HPP

#include <realm/object-store/sync/app_config.hpp>
#include <realm/object-store/sync/sync_user.hpp>
#include <realm/util/function_ref.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace realm {
class AppUser;
class SyncFileManager;

enum class SyncFileAction {
    // The Realm files at the given directory will be deleted.
    DeleteRealm,
    // The Realm file will be copied to a 'recovery' directory, and the original Realm files will be deleted.
    BackUpThenDeleteRealm
};

namespace app {
struct AppMetadata {
    std::string hostname;
    std::string ws_hostname;
};

class App;

class BackingStore {
public:
    using Data = std::pair<SyncUserData, AppUserData>;

    virtual ~BackingStore();

    // these two go away with baseurl updating
    virtual std::optional<app::AppMetadata> get_app_metadata() = 0;
    virtual void set_app_metadata(const app::AppMetadata& metadata) = 0;

    // clean up dead users and perform pending file actions
    virtual void perform_launch_actions(SyncFileManager& fm) = 0;
    // Attempt to perform all pending file actions for the given path. Returns
    // true if any were performed.
    virtual bool immediately_run_file_actions(SyncFileManager& fm, std::string_view realm_path) = 0;

    virtual void create_file_action(SyncFileAction action, std::string_view original_path, std::string_view recovery_path, std::string_view partition_value, std::string_view user_id) = 0;

    virtual Data get_user(std::string_view user_id) = 0;

    // Create a user if no user with this id exists, or update only the given
    // fields if one does
    virtual void create_user(std::string_view user_id, std::string_view refresh_token,
                             std::string_view access_token, std::string_view device_id) = 0;

    // Update the stored data for an existing user
    virtual void update_user(std::string_view user_id, const SyncUserData&, const AppUserData& data) = 0;

    // Discard tokens, set state to the given one, and if the user is the current
    // user set it to the new active user
    virtual void log_out(std::string_view user_id, std::string_view new_active_user_id,
                         UserState new_state) = 0;
    virtual void delete_user(SyncFileManager& file_manager, std::string_view user_id,
                             std::string_view new_active_user) = 0;

    virtual std::string get_current_user() = 0;
    virtual void set_current_user(std::string_view user_id) = 0;

    virtual std::vector<std::string> get_logged_in_users() = 0;

    virtual void add_realm_path(std::string_view user_id, std::string_view path) = 0;
};

std::unique_ptr<BackingStore> create_backing_store(std::string path,
                                                   RealmBackingStoreConfig::MetadataMode mode,
                                                   std::optional<std::vector<char>> encryption_key,
                                                   SyncFileManager& file_manager);

class UserManager {
public:
    UserManager(std::shared_ptr<App> app, SyncFileManager& file_manager,
                BackingStore& backing_store);
    ~UserManager();

    // Get a sync user for a given identity, or create one if none exists yet, and set its token.
    // If a logged-out user exists, it will marked as logged back in.
    std::shared_ptr<AppUser> get_user(std::string_view user_id, std::string_view refresh_token,
                                               std::string_view access_token, std::string_view device_id)
    REQUIRES(!m_user_mutex);

    // Get an existing user for a given identifier, if one exists and is logged in.
    std::shared_ptr<AppUser> get_existing_logged_in_user(std::string_view user_id) const
    REQUIRES(!m_user_mutex);

    // Get all the users that are logged in and not errored out.
    std::vector<std::shared_ptr<AppUser>> all_users() REQUIRES(!m_user_mutex);

    // Gets the currently active user.
    std::shared_ptr<AppUser> get_current_user() REQUIRES(!m_user_mutex);

    // Log out a given user
    void log_out_user(AppUser& user, bool is_anonymous) REQUIRES(!m_user_mutex);

    // Sets the currently active user.
    void set_current_user(const std::shared_ptr<AppUser>& user) REQUIRES(!m_user_mutex);

    // Removes a user
    void remove_user(AppUser& user) REQUIRES(!m_user_mutex);

    // Permanently deletes a user.
    void delete_user(AppUser& user) REQUIRES(!m_user_mutex);

    // Destroy all users persisted state and mark oustanding User instances as Removed
    // clean up persisted state.
    void reset_for_testing() REQUIRES(!m_user_mutex);

private:
    SyncFileManager& m_file_manager;
    BackingStore& m_store;

    std::shared_ptr<AppUser> get_user_for_id(std::string_view user_id) const noexcept REQUIRES(m_user_mutex);
    void remove_user(AppUser& user, bool delete_immediately);

    std::weak_ptr<App> m_app;

    // Protects m_users
    util::CheckedMutex m_user_mutex;

    // A vector of all AppUser objects.
    std::vector<std::shared_ptr<AppUser>> m_users GUARDED_BY(m_user_mutex);
    std::shared_ptr<AppUser> m_current_user GUARDED_BY(m_user_mutex);
};

} // namespace app
} // namespace realm

#endif // REALM_OS_APP_BACKING_STORE_HPP

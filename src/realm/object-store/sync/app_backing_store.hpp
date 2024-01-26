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

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <realm/object-store/sync/app_user.hpp>
#include <realm/util/function_ref.hpp>

namespace realm {

class SyncUser;

namespace app {

class App;
class SyncAppMetadata;
class SyncMetadataManager;
class SyncUserMetadata;

class BackingStore {
public:
    BackingStore(std::weak_ptr<app::App> parent)
        : m_parent_app(parent)
    {
    }
    // Get a sync user for a given identity, or create one if none exists yet, and set its token.
    // If a logged-out user exists, it will marked as logged back in.
    virtual std::shared_ptr<AppUser> get_user(std::string_view user_id, std::string_view refresh_token,
                                              std::string_view access_token, std::string_view device_id) = 0;

    // Get an existing user for a given identifier, if one exists and is logged in.
    virtual std::shared_ptr<AppUser> get_existing_logged_in_user(std::string_view user_id) const = 0;

    virtual std::shared_ptr<AppUser> get_existing_user(std::string_view user_id) const = 0;

    // Get all the users that are logged in and not errored out.
    virtual std::vector<std::shared_ptr<AppUser>> all_users() = 0;

    // Gets the currently active user.
    virtual std::shared_ptr<AppUser> get_current_user() const = 0;

    // Log out a given user
    virtual void log_out_user(const AppUser& user) = 0;

    // Sets the currently active user.
    virtual void set_current_user(std::string_view user_id) = 0;

    // Removes a user
    virtual void remove_user(std::string_view user_id) = 0;

    // Permanently deletes a user.
    virtual void delete_user(std::string_view user_id) = 0;

    // Destroy all users persisted state and mark oustanding User instances as Removed
    // clean up persisted state.
    virtual void reset_for_testing() = 0;

    // FIXME: this is an implementation detail leak and doesn't belong in this API
    // FIXME: consider abstracting it to something called `on_manual_client_reset()`
    // Immediately run file actions for a single Realm at a given original path.
    // Returns whether or not a file action was successfully executed for the specified Realm.
    // Preconditions: all references to the Realm at the given path must have already been invalidated.
    // The metadata and file management subsystems must also have already been configured.
    virtual bool immediately_run_file_actions(std::string_view original_name) = 0;

    // If the metadata manager is configured, perform an update. Returns `true` if the code was run.
    virtual bool perform_metadata_update(util::FunctionRef<void(SyncMetadataManager&)> update_function) const = 0;

    // Get the default path for a Realm for the given SyncUser.
    // The default value is `<rootDir>/<appId>/<userId>/<partitionValue>.realm`.
    // If the file cannot be created at this location, for example due to path length restrictions,
    // this function may pass back `<rootDir>/<hashedFileName>.realm`
    // The `user` is required.
    // If partition_value is empty, FLX sync is requested
    // otherwise this is for a PBS Realm and the string
    // is a BSON formatted value.
    virtual std::string path_for_realm(std::shared_ptr<AppUser> user,
                                       std::optional<std::string> custom_file_name = std::nullopt,
                                       std::optional<std::string> partition_value = std::nullopt) const = 0;

    // Get the path of the recovery directory for backed-up or recovered Realms.
    virtual std::string
    recovery_directory_path(std::optional<std::string> const& custom_dir_name = std::nullopt) const = 0;

    // Get the app metadata for the active app.
    virtual std::optional<SyncAppMetadata> app_metadata() const = 0;

protected:
    // these methods allow only derived backing stores to construct SyncUsers
    // because SyncUser has a private constructor but BackingStore is a friend class
    std::shared_ptr<AppUser> make_user(std::string_view refresh_token, std::string_view id,
                                       std::string_view access_token, std::string_view device_id,
                                       std::shared_ptr<app::App> app) const
    {
        return std::make_shared<AppUser>(AppUser::Private{}, refresh_token, id, access_token, device_id,
                                         std::move(app));
    }
    std::shared_ptr<AppUser> make_user(const SyncUserMetadata& data, std::shared_ptr<app::App> app) const
    {
        return std::make_shared<AppUser>(AppUser::Private{}, data, std::move(app));
    }

    std::weak_ptr<app::App> m_parent_app;
};

} // namespace app
} // namespace realm

#endif // REALM_OS_APP_BACKING_STORE_HPP
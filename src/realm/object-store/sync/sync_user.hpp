////////////////////////////////////////////////////////////////////////////
//
// Copyright 2016 Realm Inc.
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

#ifndef REALM_OS_SYNC_USER_HPP
#define REALM_OS_SYNC_USER_HPP

#include <realm/object-store/sync/subscribable.hpp>
#include <realm/object-store/util/atomic_shared_ptr.hpp>

#include <realm/util/bson/bson.hpp>
#include <realm/util/checked_mutex.hpp>
#include <realm/util/optional.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace realm {
namespace app {
class App;
struct AppError;
class BackingStore;
class MongoClient;
} // namespace app
class SyncManager;
class SyncSession;
class SyncUserMetadata;

// A superclass that bindings can inherit from in order to store information
// upon a `SyncUser` object.
class SyncUserContext {
public:
    virtual ~SyncUserContext() = default;
};

using SyncUserContextFactory = util::UniqueFunction<std::shared_ptr<SyncUserContext>()>;

// A struct that decodes a given JWT.
struct RealmJWT {
    // The token being decoded from.
    std::string token;

    // When the token expires.
    int64_t expires_at = 0;
    // When the token was issued.
    int64_t issued_at = 0;
    // Custom user data embedded in the encoded token.
    util::Optional<bson::BsonDocument> user_data;

    explicit RealmJWT(std::string_view token);
    explicit RealmJWT(StringData token);
    explicit RealmJWT(const std::string& token);
    RealmJWT() = default;

    bool operator==(const RealmJWT& other) const
    {
        return token == other.token;
    }
};

struct AppUserProfile {
    // The full name of the user.
    util::Optional<std::string> name() const
    {
        return get_field("name");
    }
    // The email address of the user.
    util::Optional<std::string> email() const
    {
        return get_field("email");
    }
    // A URL to the user's profile picture.
    util::Optional<std::string> picture_url() const
    {
        return get_field("picture_url");
    }
    // The first name of the user.
    util::Optional<std::string> first_name() const
    {
        return get_field("first_name");
    }
    // The last name of the user.
    util::Optional<std::string> last_name() const
    {
        return get_field("last_name");
    }
    // The gender of the user.
    util::Optional<std::string> gender() const
    {
        return get_field("gender");
    }
    // The birthdate of the user.
    util::Optional<std::string> birthday() const
    {
        return get_field("birthday");
    }
    // The minimum age of the user.
    util::Optional<std::string> min_age() const
    {
        return get_field("min_age");
    }
    // The maximum age of the user.
    util::Optional<std::string> max_age() const
    {
        return get_field("max_age");
    }

    bson::Bson operator[](const std::string& key) const
    {
        return m_data.at(key);
    }

    const bson::BsonDocument& data() const
    {
        return m_data;
    }

    AppUserProfile(bson::BsonDocument&& data)
        : m_data(std::move(data))
    {
    }
    AppUserProfile() = default;

private:
    bson::BsonDocument m_data;

    util::Optional<std::string> get_field(const char* name) const
    {
        auto it = m_data.find(name);
        if (it == m_data.end()) {
            return util::none;
        }
        return static_cast<std::string>((*it).second);
    }
};

// A struct that represents an identity that a `User` is linked to
struct AppUserIdentity {
    // the id of the identity
    std::string id;
    // the associated provider type of the identity
    std::string provider_type;

    AppUserIdentity(const std::string& id, const std::string& provider_type);

    bool operator==(const AppUserIdentity& other) const
    {
        return id == other.id && provider_type == other.provider_type;
    }

    bool operator!=(const AppUserIdentity& other) const
    {
        return id != other.id || provider_type != other.provider_type;
    }
};

enum class UserState {
    LoggedOut,
    LoggedIn,
    Removed,
};

struct SyncUserData {
    // Current refresh token or empty if user is logged out
    RealmJWT refresh_token;
    // Current access token or empty if user is logged out
    RealmJWT access_token;
    // Current state of the user
    UserState state;
    // UUIDs which used to be used to generate local Realm file paths. Now only
    // used to locate existing files.
    std::vector<std::string> legacy_identities;
};

struct AppUserData {
    // Identities which were used to log into this user
    std::vector<AppUserIdentity> identities;
    // Id for the device which this user was logged in on. Users are not
    // portable between devices so this cannot be changed after the user
    // is created
    std::string device_id;
    // Server-stored user profile
    AppUserProfile profile;
};

class SyncUser;

class UserProvider {
public:
    virtual ~UserProvider() = 0;

    virtual void register_sync_user(SyncUser&) = 0;
    virtual void unregister_sync_user(SyncUser&) = 0;

    using CompletionHandler = util::UniqueFunction<void(std::optional<app::AppError>)>;
    virtual void request_log_out(std::string_view user_id, CompletionHandler&&) = 0;
    virtual void request_refresh_user(std::string_view user_id, CompletionHandler&&) = 0;
    virtual void request_refresh_location(std::string_view user_id, CompletionHandler&&) = 0;
    virtual void request_access_token(std::string_view user_id, CompletionHandler&&) = 0;
};

class SyncUser {
public:
    /// Returns true if the users access_token and refresh_token are set.
    bool is_logged_in() const REQUIRES(!m_mutex);

    /// Server-supplied unique id for this user.
    const std::string& user_id() const noexcept
    {
        return m_user_id;
    }

    const std::string& app_id() const noexcept
    {
        return m_app_id;
    }

    const std::vector<std::string>& legacy_identities() const noexcept
    {
        return m_data.legacy_identities;
    }

    std::string access_token() const REQUIRES(!m_mutex);
    std::string refresh_token() const REQUIRES(!m_mutex);
    UserState state() const REQUIRES(!m_mutex);

    SyncUser(std::shared_ptr<UserProvider>, std::shared_ptr<SyncManager>, std::string_view app_id, std::string_view user_id);
    ~SyncUser();
    SyncUser(const SyncUser&) = delete;
    SyncUser& operator=(const SyncUser&) = delete;

    // Atomically set the user to be logged in and update both tokens.
    void update_backing_data(SyncUserData&& data) REQUIRES(!m_mutex);

    /// Checks the expiry on the access token against the local time and if it is invalid or expires soon, returns
    /// true.
    bool access_token_refresh_required() const REQUIRES(!m_mutex);

    // Hook for testing access token timeouts
    void set_seconds_to_adjust_time_for_testing(int seconds)
    {
        m_seconds_to_adjust_time_for_testing.store(seconds);
    }

    void detach_from_provider() REQUIRES(!m_mutex);

    std::shared_ptr<SyncManager> sync_manager() REQUIRES(!m_mutex)
    {
        util::CheckedLockGuard lock(m_mutex);
        return m_sync_manager;
    }

    void request_log_out(util::UniqueFunction<void(util::Optional<app::AppError>)>&&) REQUIRES(!m_mutex);
    void request_refresh_user(util::UniqueFunction<void(util::Optional<app::AppError>)>&&) REQUIRES(!m_mutex);
    void request_refresh_location(util::UniqueFunction<void(util::Optional<app::AppError>)>&&) REQUIRES(!m_mutex);
    void request_access_token(util::UniqueFunction<void(util::Optional<app::AppError>)>&&) REQUIRES(!m_mutex);

protected:
    util::CheckedMutex m_mutex;
    std::shared_ptr<UserProvider> m_provider;
    std::shared_ptr<SyncManager> m_sync_manager;
    const std::string m_app_id;
    const std::string m_user_id;
    SyncUserData m_data GUARDED_BY(m_mutex);
    std::atomic<int> m_seconds_to_adjust_time_for_testing = 0;
};

class AppUser final : public SyncUser, public std::enable_shared_from_this<AppUser>, public Subscribable<AppUser> {
    struct Private {};
    using SyncUser::m_mutex;

public:
    // Log the user out and mark it as such. This will also close its associated Sessions.
    void log_out() REQUIRES(!m_mutex);

    /// Returns true if the user's only identity is anonymous.
    bool is_anonymous() const REQUIRES(!m_mutex);

    std::string device_id() const REQUIRES(!m_mutex);
    bool has_device_id() const REQUIRES(!m_mutex);
    AppUserProfile user_profile() const REQUIRES(!m_mutex);
    std::vector<AppUserIdentity> identities() const REQUIRES(!m_mutex);

    // Custom user data embedded in the access token.
    util::Optional<bson::BsonDocument> custom_data() const REQUIRES(!m_mutex);

    // Get the app instance that this user belongs to.
//    std::shared_ptr<app::App> app() const REQUIRES(!m_mutex);

    /// Retrieves a general-purpose service client for the Realm Cloud service
    /// @param service_name The name of the cluster
//    app::MongoClient mongo_client(const std::string& service_name) REQUIRES(!m_mutex);

    // ------------------------------------------------------------------------
    // All of the following are called by `RealmBackingStore` and are public only for
    // testing purposes. SDKs should not call these directly in non-test code
    // or expose them in the public API.

    static std::shared_ptr<AppUser> make(std::shared_ptr<app::App> app, std::string_view user_id)
    {
        return std::make_shared<AppUser>(Private(), std::move(app), user_id);
    }

    AppUser(Private, std::shared_ptr<app::App> app, std::string_view user_id);
    ~AppUser();

    // Atomically set the user to be logged in and update both tokens.
    void update_backing_data(std::pair<SyncUserData, AppUserData>&& data) REQUIRES(!m_mutex);

    /// Refreshes the custom data for this user
    /// If `update_location` is true, the location metadata will be queried before the request
    void refresh_custom_data(bool update_location,
                             util::UniqueFunction<void(util::Optional<app::AppError>)> completion_block)
        REQUIRES(!m_mutex);
    void refresh_custom_data(util::UniqueFunction<void(util::Optional<app::AppError>)> completion_block)
        REQUIRES(!m_mutex);

    // FIXME: Not for public use.
    void detach_from_backing_store() REQUIRES(!m_mutex);

private:
    bool do_is_anonymous() const REQUIRES(m_mutex);
    AppUserData m_app_data GUARDED_BY(m_mutex);
    std::shared_ptr<app::App> m_app;
};

} // namespace realm

namespace std {
template <>
struct hash<realm::AppUserIdentity> {
    size_t operator()(realm::AppUserIdentity const&) const;
};
} // namespace std

#endif // REALM_OS_SYNC_USER_HPP

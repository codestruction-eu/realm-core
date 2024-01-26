////////////////////////////////////////////////////////////////////////////
//
// Copyright 2024 Realm Inc.
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

#ifndef REALM_OS_APP_USER_HPP
#define REALM_OS_APP_USER_HPP

#include <realm/object-store/sync/sync_user.hpp>

namespace realm::app {
class App;
struct AppError;
class BackingStore;
class MongoClient;
class SyncUserMetadata;

struct SyncUserProfile {
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

    SyncUserProfile(bson::BsonDocument&& data)
        : m_data(std::move(data))
    {
    }
    SyncUserProfile() = default;

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
struct SyncUserIdentity {
    // the id of the identity
    std::string id;
    // the associated provider type of the identity
    std::string provider_type;

    SyncUserIdentity(const std::string& id, const std::string& provider_type);

    bool operator==(const SyncUserIdentity& other) const
    {
        return id == other.id && provider_type == other.provider_type;
    }

    bool operator!=(const SyncUserIdentity& other) const
    {
        return id != other.id || provider_type != other.provider_type;
    }
};

class AppUser : public std::enable_shared_from_this<AppUser>, public SyncUser {
    friend class BackingStore; // only this is expected to construct an AppUser
    struct Private {};

public:
    // Private constructors enforce the use of the `BackingStore` APIs.
    AppUser(Private, std::string_view refresh_token, std::string_view id, std::string_view access_token,
            std::string_view device_id, std::shared_ptr<app::App> app);
    AppUser(Private, const SyncUserMetadata& data, std::shared_ptr<app::App> app);
    AppUser(const AppUser&) = delete;
    AppUser& operator=(const AppUser&) = delete;

    SyncUserProfile user_profile() const REQUIRES(!m_mutex);
    bool is_anonymous() const REQUIRES(!m_mutex);
    std::string device_id() const REQUIRES(!m_mutex);
    bool has_device_id() const REQUIRES(!m_mutex);
    std::vector<SyncUserIdentity> identities() const REQUIRES(!m_mutex);
    const std::vector<std::string>& legacy_identities() const noexcept
    {
        return m_legacy_identities;
    }

    // Custom user data embedded in the access token.
    util::Optional<bson::BsonDocument> custom_data() const;

    // Get the app instance that this user belongs to.
    // This may not lock() if this SyncUser has become detached.
    std::weak_ptr<app::App> app() const;

    /// Retrieves a general-purpose service client for the Realm Cloud service
    /// @param service_name The name of the cluster
    app::MongoClient mongo_client(const std::string& service_name) REQUIRES(!m_mutex);

    // Update the user's profile and identities.
    void update_user_profile(std::vector<SyncUserIdentity> identities, SyncUserProfile profile) REQUIRES(!m_mutex);

    // FIXME: Not for public use.
    void detach_from_backing_store() REQUIRES(!m_mutex);

private:
    mutable util::CheckedMutex m_mutex;
    bool do_is_anonymous() const REQUIRES(m_mutex);

    // UUIDs which used to be used to generate local Realm file paths. Now only
    // used to locate existing files.
    std::vector<std::string> m_legacy_identities;

    // The identities associated with this user.
    std::vector<SyncUserIdentity> m_user_identities GUARDED_BY(m_mutex);

    SyncUserProfile m_user_profile GUARDED_BY(m_mutex);
    const std::string m_device_id;
    std::weak_ptr<app::App> m_app;
};

} // namespace realm::app

namespace std {
template <>
struct hash<realm::app::SyncUserIdentity> {
    size_t operator()(realm::app::SyncUserIdentity const&) const;
};
} // namespace std

#endif // REALM_OS_APP_USER_HPP

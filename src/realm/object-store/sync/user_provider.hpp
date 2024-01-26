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

#ifndef REALM_USER_PROVIDER_HPP
#define REALM_USER_PROVIDER_HPP

#include <realm/util/bson/bson.hpp>
#include <realm/util/function_ref.hpp>

#include <string>
#include <memory>

namespace realm {
class SyncUser;
class SyncManager;

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

struct UserData {
    enum class State {
        LoggedOut,
        LoggedIn,
        Removed,
    };

    std::string app_id;
    std::string user_id;
    RealmJWT access_token;
    RealmJWT refresh_token;
    State state;
};

class UserProvider {
public:
    virtual ~UserProvider() = 0;
    virtual void request_access_token_refresh(std::string_view user_id) = 0;
    virtual void request_user_log_out(std::string_view user_id) = 0;
    virtual void request_location_refresh(std::string_view user_id) = 0;
    virtual std::shared_ptr<SyncManager> const& sync_manager() const = 0;

protected:
    void update(std::shared_ptr<SyncUser> user, const UserData& data);
    UserData get_data(std::shared_ptr<SyncUser> user);
};

} // namespace realm

#endif // REALM_USER_PROVIDER_HPP

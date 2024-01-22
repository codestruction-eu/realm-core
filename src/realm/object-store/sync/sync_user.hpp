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

#include <realm/object-store/util/atomic_shared_ptr.hpp>
#include <realm/util/bson/bson.hpp>
#include <realm/object-store/sync/subscribable.hpp>
#include <realm/sync/protocol.hpp>
#include <realm/util/checked_mutex.hpp>
#include <realm/util/optional.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace realm {
class SyncManager;
class SyncSession;

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
    std::string sync_route;
};

class UserProvider {
public:
    virtual ~UserProvider() = 0;
    virtual UserData get_user_data(std::string_view user_id) = 0;
    virtual void set_user_change_callback(std::string_view user_id,
                                          util::UniqueFunction<void(UserData)> callback) = 0;

    virtual void server_requests_action(std::string_view user_id, sync::ProtocolErrorInfo::Action) = 0;
    virtual void request_access_token_refresh(std::string_view user_id) = 0;
};

class SyncUser : public std::enable_shared_from_this<SyncUser>, public Subscribable<SyncUser> {
    friend class SyncSession;
    struct Private {};

public:
    // Return a list of all sessions belonging to this user.
    std::vector<std::shared_ptr<SyncSession>> all_sessions() REQUIRES(!m_mutex);

    // Return a session for a given on disk path.
    // In most cases, bindings shouldn't expose this to consumers, since the on-disk
    // path for a synced Realm is an opaque implementation detail. This API is retained
    // for testing purposes, and for bindings for consumers that are servers or tools.
    std::shared_ptr<SyncSession> session_for_on_disk_path(const std::string& path) REQUIRES(!m_mutex);

    bool is_logged_in() const REQUIRES(!m_mutex);

    const std::string& user_id() const noexcept
    {
        return m_user_id;
    }

    std::string app_id() const REQUIRES(!m_mutex);
    std::string access_token() const REQUIRES(!m_mutex);
    std::string refresh_token() const REQUIRES(!m_mutex);
    UserData::State state() const REQUIRES(!m_mutex);

    std::shared_ptr<SyncUserContext> binding_context() const
    {
        return m_binding_context.load();
    }

    // Optionally set a context factory. If so, must be set before any sessions are created.
    static void set_binding_context_factory(SyncUserContextFactory factory);

    std::shared_ptr<SyncManager> sync_manager() const REQUIRES(!m_mutex);

    // ------------------------------------------------------------------------
    // All of the following are called by `SyncManager` and are public only for
    // testing purposes. SDKs should not call these directly in non-test code
    // or expose them in the public API.

    explicit SyncUser(Private, std::string_view user_id, SyncManager* sync_manager, UserProvider* provider);
    ~SyncUser();
    SyncUser(const SyncUser&) = delete;
    SyncUser& operator=(const SyncUser&) = delete;

    // Register a session to this user.
    // A registered session will be bound at the earliest opportunity: either
    // immediately, or upon the user becoming Active.
    // Note that this is called by the SyncManager, and should not be directly called.
    void register_session(std::shared_ptr<SyncSession>) REQUIRES(!m_mutex);

    /// Checks the expiry on the access token against the local time and if it is invalid or expires soon, returns
    /// true.
    bool access_token_refresh_required() const REQUIRES(!m_mutex);
    void request_access_token_refresh() const REQUIRES(!m_mutex);
    void request_action(sync::ProtocolErrorInfo::Action) const REQUIRES(!m_mutex);

    // Hook for testing access token timeouts
    void set_seconds_to_adjust_time_for_testing(int seconds)
    {
        m_seconds_to_adjust_time_for_testing.store(seconds);
    }

protected:
    friend class SyncManager;
    void detach_from_sync_manager() REQUIRES(!m_mutex);

private:
    static SyncUserContextFactory s_binding_context_factory;
    static std::mutex s_binding_context_factory_mutex;

    std::vector<std::shared_ptr<SyncSession>> revive_sessions() REQUIRES(m_mutex);

    util::AtomicSharedPtr<SyncUserContext> m_binding_context;

    util::CheckedMutex m_mutex;
    const std::string m_user_id;
    UserData m_data GUARDED_BY(m_mutex);
    SyncManager* m_sync_manager;
    UserProvider* m_provider;

    // Sessions are owned by the SyncManager, but the user keeps a map of weak references
    // to them.
    std::unordered_map<std::string, std::weak_ptr<SyncSession>> m_sessions;

    std::atomic<int> m_seconds_to_adjust_time_for_testing = 0;
};

} // namespace realm

#endif // REALM_OS_SYNC_USER_HPP

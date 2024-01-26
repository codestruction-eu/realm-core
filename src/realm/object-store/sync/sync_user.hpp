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
#include <realm/object-store/sync/user_provider.hpp>

#include <realm/util/checked_mutex.hpp>
#include <realm/util/optional.hpp>
#include <realm/table.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace realm {
class SyncManager;

// A `SyncUser` represents a single user account. Each user manages the sessions that
// are associated with it.
class SyncUser : public Subscribable<SyncUser> {
public:
    friend class UserProvider;
    using State = UserData::State;
    explicit SyncUser(const UserData& data, std::shared_ptr<UserProvider> provider);
    ~SyncUser();
    bool is_logged_in() const REQUIRES(!m_data_mutex);
    const std::string& user_id() const noexcept
    {
        return m_user_id;
    }

    std::string app_id() const REQUIRES(!m_data_mutex);
    std::string access_token() const REQUIRES(!m_data_mutex);
    std::string refresh_token() const REQUIRES(!m_data_mutex);
    UserData::State state() const REQUIRES(!m_data_mutex);

    void request_location_update();
    void request_access_token_refresh();
    void request_log_out();

    /// Checks the expiry on the access token against the local time and if it is invalid or expires soon, returns
    /// true.
    bool access_token_refresh_required() const REQUIRES(!m_data_mutex);

    // Hook for testing access token timeouts
    void set_seconds_to_adjust_time_for_testing(int seconds)
    {
        m_seconds_to_adjust_time_for_testing.store(seconds);
    }

    std::weak_ptr<UserProvider> provider() const
    {
        return m_provider;
    }

protected:
    UserData data() const REQUIRES(!m_data_mutex);

private:
    // called by friend class UserProvider
    void update(const UserData& data) REQUIRES(!m_data_mutex);

    util::CheckedMutex m_data_mutex;
    const std::string m_user_id;
    UserData m_data GUARDED_BY(m_data_mutex);
    std::weak_ptr<UserProvider> m_provider;
    std::atomic<int> m_seconds_to_adjust_time_for_testing = 0;
};

} // namespace realm

#endif // REALM_OS_SYNC_USER_HPP

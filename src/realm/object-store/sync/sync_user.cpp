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

#include <realm/object-store/sync/sync_user.hpp>

#include <realm/object-store/sync/sync_manager.hpp>
#include <realm/object-store/sync/sync_session.hpp>


namespace realm {

SyncUser::SyncUser(const UserData& data, std::shared_ptr<UserProvider> provider)
    : m_user_id(data.user_id)
    , m_data(data)
    , m_provider(provider)
{
}

// called by friend class UserProvider
void SyncUser::update(const UserData& data)
{
    {
        util::CheckedLockGuard lk(m_data_mutex);
        m_data = data;
    }
    if (auto provider = m_provider.lock()) {
        auto manager = provider->sync_manager();
        for (auto& session : manager->get_all_sessions_for(*this)) {
            session->force_close();
            if (data.state == UserData::State::LoggedIn) {
                session->revive_if_needed();
            }
        }
    }
    this->emit_change_to_subscribers(*this);
}

std::string SyncUser::app_id() const
{
    util::CheckedLockGuard lk(m_data_mutex);
    return m_data.app_id;
}

std::string SyncUser::access_token() const
{
    util::CheckedLockGuard lk(m_data_mutex);
    return m_data.access_token.token;
}

std::string SyncUser::refresh_token() const
{
    util::CheckedLockGuard lk(m_data_mutex);
    return m_data.refresh_token.token;
}

UserData::State SyncUser::state() const
{
    util::CheckedLockGuard lk(m_data_mutex);
    if (!m_provider.lock()) {
        return State::Removed;
    }
    return m_data.state;
}

UserData SyncUser::data() const
{
    util::CheckedLockGuard lk(m_data_mutex);
    return m_data;
}

void SyncUser::request_location_update()
{
    if (auto provider = m_provider.lock()) {
        provider->request_location_refresh(m_user_id);
    }
}

void SyncUser::request_access_token_refresh()
{
    if (auto provider = m_provider.lock()) {
        provider->request_access_token_refresh(m_user_id);
    }
}

void SyncUser::request_log_out()
{
    if (auto provider = m_provider.lock()) {
        provider->request_user_log_out(m_user_id);
    }
    // FIXME: change state immediately?
}

bool SyncUser::is_logged_in() const
{
    util::CheckedLockGuard lock(m_data_mutex);
    return m_data.state == State::LoggedIn;
}

bool SyncUser::access_token_refresh_required() const
{
    using namespace std::chrono;
    constexpr size_t buffer_seconds = 5; // arbitrary
    util::CheckedLockGuard lock(m_data_mutex);
    const auto now = duration_cast<seconds>(system_clock::now().time_since_epoch()).count() +
                     m_seconds_to_adjust_time_for_testing.load(std::memory_order_relaxed);
    const auto threshold = now - buffer_seconds;
    return !m_data.access_token.token.empty() && m_data.access_token.expires_at < static_cast<int64_t>(threshold);
}

} // namespace realm

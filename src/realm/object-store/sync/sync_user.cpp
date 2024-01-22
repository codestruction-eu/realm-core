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

#include <realm/util/base64.hpp>

namespace realm {

static std::string base64_decode(const std::string& in)
{
    std::string out;
    out.resize(util::base64_decoded_size(in.size()));
    util::base64_decode(in, &out[0], out.size());
    return out;
}

static std::vector<std::string> split_token(const std::string& jwt)
{
    constexpr static char delimiter = '.';

    std::vector<std::string> parts;
    size_t pos = 0, start_from = 0;

    while ((pos = jwt.find(delimiter, start_from)) != std::string::npos) {
        parts.push_back(jwt.substr(start_from, pos - start_from));
        start_from = pos + 1;
    }

    parts.push_back(jwt.substr(start_from));

    if (parts.size() != 3) {
        throw RuntimeError(ErrorCodes::BadToken, "jwt missing parts");
    }

    return parts;
}

RealmJWT::RealmJWT(const std::string& token)
    : token(token)
{
    auto parts = split_token(this->token);

    auto json_str = base64_decode(parts[1]);
    auto json = static_cast<bson::BsonDocument>(bson::parse(json_str));

    this->expires_at = static_cast<int64_t>(json["exp"]);
    this->issued_at = static_cast<int64_t>(json["iat"]);

    if (json.find("user_data") != json.end()) {
        this->user_data = static_cast<bson::BsonDocument>(json["user_data"]);
    }
}

SyncUserContextFactory SyncUser::s_binding_context_factory;
std::mutex SyncUser::s_binding_context_factory_mutex;

SyncUser::SyncUser(Private, std::string_view user_id, SyncManager* sync_manager, UserProvider* provider)
    : m_user_id(user_id)
    , m_data(provider->get_user_data(user_id))
    , m_sync_manager(sync_manager)
    , m_provider(provider)
{
    {
        std::lock_guard lock(s_binding_context_factory_mutex);
        if (s_binding_context_factory) {
            m_binding_context = s_binding_context_factory();
        }
    }
    auto weak_self = weak_from_this(); // pretend this works
    provider->set_user_change_callback(user_id, [weak_self](auto new_data) {
        if (auto self = weak_self.lock()) {
            self->m_data = std::move(new_data);
            for (auto& session : self->all_sessions()) {
                session->force_close();
                if (self->m_data.state == UserData::State::LoggedIn) {
                    session->revive_if_needed();
                }
            }
            self->emit_change_to_subscribers(*self);
        }
    });
}

SyncUser::~SyncUser()
{
    m_provider->set_user_change_callback(user_id(), nullptr);
}

std::shared_ptr<SyncManager> SyncUser::sync_manager() const
{
    util::CheckedLockGuard lk(m_mutex);
    if (m_data.state == UserData::State::Removed) {
        throw RuntimeError(
            ErrorCodes::ClientUserNotFound,
            util::format("Cannot start a sync session for user '%1' because this user has been removed.", m_user_id));
    }
    REALM_ASSERT(m_sync_manager);
    return m_sync_manager->shared_from_this();
}

void SyncUser::detach_from_sync_manager()
{
    util::CheckedLockGuard lk(m_mutex);
    REALM_ASSERT(m_sync_manager);
    m_provider->set_user_change_callback(user_id(), nullptr);
    m_data.state = UserData::State::Removed;
    m_sync_manager = nullptr;
    m_provider = nullptr;
}

std::vector<std::shared_ptr<SyncSession>> SyncUser::all_sessions()
{
    util::CheckedLockGuard lock(m_mutex);
    std::vector<std::shared_ptr<SyncSession>> sessions;
    if (m_data.state == UserData::State::Removed) {
        return sessions;
    }
    for (auto it = m_sessions.begin(); it != m_sessions.end();) {
        if (auto ptr_to_session = it->second.lock()) {
            sessions.emplace_back(std::move(ptr_to_session));
            it++;
            continue;
        }
        // This session is bad, destroy it.
        it = m_sessions.erase(it);
    }
    return sessions;
}

std::shared_ptr<SyncSession> SyncUser::session_for_on_disk_path(const std::string& path)
{
    util::CheckedLockGuard lock(m_mutex);
    if (m_data.state == UserData::State::Removed) {
        return nullptr;
    }
    auto it = m_sessions.find(path);
    if (it == m_sessions.end()) {
        return nullptr;
    }
    auto locked = it->second.lock();
    if (!locked) {
        // Remove the session from the map, because it has fatally errored out or the entry is invalid.
        m_sessions.erase(it);
    }
    return locked;
}

std::string SyncUser::app_id() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.app_id;
}

std::string SyncUser::refresh_token() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.refresh_token.token;
}

std::string SyncUser::access_token() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.access_token.token;
}

UserData::State SyncUser::state() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.state;
}

bool SyncUser::is_logged_in() const
{
    return state() == UserData::State::LoggedIn;
}

void SyncUser::register_session(std::shared_ptr<SyncSession> session)
{
    const std::string& path = session->path();
    util::CheckedUniqueLock lock(m_mutex);
    switch (m_data.state) {
        case UserData::State::LoggedIn:
            m_sessions[path] = session;
            break;
        case UserData::State::LoggedOut:
            m_sessions[path] = session;
            break;
        case UserData::State::Removed:
            break;
    }
}

void SyncUser::set_binding_context_factory(SyncUserContextFactory factory)
{
    std::lock_guard<std::mutex> lock(s_binding_context_factory_mutex);
    s_binding_context_factory = std::move(factory);
}

bool SyncUser::access_token_refresh_required() const
{
    using namespace std::chrono;
    constexpr size_t buffer_seconds = 5; // arbitrary
    util::CheckedLockGuard lock(m_mutex);
    const auto now = duration_cast<seconds>(system_clock::now().time_since_epoch()).count() +
                     m_seconds_to_adjust_time_for_testing.load(std::memory_order_relaxed);
    const auto threshold = now - buffer_seconds;
    return !m_data.access_token.token.empty() && m_data.access_token.expires_at < static_cast<int64_t>(threshold);
}

void SyncUser::request_access_token_refresh() const
{
    if (m_provider) {
        m_provider->request_access_token_refresh(m_user_id);
    }
}

void SyncUser::request_action(sync::ProtocolErrorInfo::Action action) const
{
    if (m_provider) {
        m_provider->server_requests_action(m_user_id, action);
    }
}

} // namespace realm

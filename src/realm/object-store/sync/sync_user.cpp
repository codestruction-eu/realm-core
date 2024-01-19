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

#include <realm/object-store/sync/app.hpp>
#include <realm/object-store/sync/app_credentials.hpp>
#include <realm/object-store/sync/generic_network_transport.hpp>
#include <realm/object-store/sync/impl/sync_metadata.hpp>
#include <realm/object-store/sync/mongo_client.hpp>
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
        throw app::AppError(ErrorCodes::BadToken, "jwt missing parts");
    }

    return parts;
}

RealmJWT::RealmJWT(std::string_view token)
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

RealmJWT::RealmJWT(StringData token)
    : RealmJWT(std::string_view(token))
{
}

RealmJWT::RealmJWT(const std::string& token)
    : RealmJWT(std::string_view(token))
{
}


AppUserIdentity::AppUserIdentity(const std::string& id, const std::string& provider_type)
    : id(id)
    , provider_type(provider_type)
{
}

SyncUser::SyncUser(std::shared_ptr<UserProvider> provider,
                   std::shared_ptr<SyncManager> manager,
                   std::string_view app_id,
                   std::string_view user_id)
    : m_provider(std::move(provider))
    , m_sync_manager(std::move(manager))
    , m_app_id(app_id)
    , m_user_id(user_id)
{
    provider->register_sync_user(*this);
}

SyncUser::~SyncUser()
{
    if (m_provider) {
        m_provider->unregister_sync_user(*this);
    }
}

void SyncUser::detach_from_provider()
{
    util::CheckedLockGuard lk(m_mutex);
    m_data.state = UserState::Removed;
    if (m_provider) {
        m_provider->unregister_sync_user(*this);
    }
    m_provider.reset();
    m_sync_manager.reset();
}

void SyncUser::update_backing_data(SyncUserData&& data)
{
    bool is_logged_in = data.state == UserState::LoggedIn;
    if (is_logged_in) {
        REALM_ASSERT(!data.access_token.token.empty());
        REALM_ASSERT(!data.refresh_token.token.empty());
    }
    bool was_logged_in;
    {
        util::CheckedLockGuard lock1(m_mutex);
        was_logged_in = data.state == UserState::LoggedIn;
        m_data = std::move(data);
    }

    if (is_logged_in && !was_logged_in) { // or if token changed?
        for (auto session : m_sync_manager->get_all_sessions_for(*this)) {
            session->revive_if_needed();
        }
    }

    if (!is_logged_in && was_logged_in) {
        for (auto session : m_sync_manager->get_all_sessions_for(*this)) {
            session->force_close();
        }
    }
}

bool SyncUser::is_logged_in() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.state == UserState::LoggedIn;
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

UserState SyncUser::state() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.state;
}

void SyncUser::request_log_out(util::UniqueFunction<void (util::Optional<app::AppError>)> && completion)
{
    // FIXME: probably unsafe to call under lock
    util::CheckedLockGuard lock(m_mutex);
    if (m_provider) {
        m_provider->request_log_out(m_user_id, std::move(completion));
    }
}

void SyncUser::request_refresh_user(util::UniqueFunction<void (util::Optional<app::AppError>)> && completion)
{
    util::CheckedLockGuard lock(m_mutex);
    if (m_provider) {
        m_provider->request_refresh_user(m_user_id, std::move(completion));
    }
}

void SyncUser::request_refresh_location(util::UniqueFunction<void (util::Optional<app::AppError>)> && completion)
{
    util::CheckedLockGuard lock(m_mutex);
    if (m_provider) {
        m_provider->request_refresh_location(m_user_id, std::move(completion));
    }
}

void SyncUser::request_access_token(util::UniqueFunction<void (util::Optional<app::AppError>)> && completion)
{
    util::CheckedLockGuard lock(m_mutex);
    if (m_provider) {
        m_provider->request_access_token(m_user_id, std::move(completion));
    }
}

AppUser::AppUser(Private, std::shared_ptr<app::App> app, std::string_view user_id)
    : SyncUser(app->user_provider(), app->sync_manager(), app->config().app_id, user_id)
    , m_app(std::move(app))
{
}

void AppUser::detach_from_backing_store()
{
    SyncUser::detach_from_provider();
    util::CheckedLockGuard lk(m_mutex);
    m_app.reset();
}

void AppUser::update_backing_data(std::pair<SyncUserData, AppUserData>&& data)
{
    {
        util::CheckedLockGuard lock(m_mutex);
        m_app_data = std::move(data.second);
    }
    SyncUser::update_backing_data(std::move(data.first));
    emit_change_to_subscribers(*this);
}

std::vector<AppUserIdentity> AppUser::identities() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_app_data.identities;
}

void AppUser::log_out()
{
    m_provider->request_log_out(m_user_id, nullptr);
}

bool AppUser::is_anonymous() const
{
    util::CheckedLockGuard lock(m_mutex);
    return do_is_anonymous();
}

bool AppUser::do_is_anonymous() const
{
    return m_data.state == UserState::LoggedIn && m_app_data.identities.size() == 1 &&
           m_app_data.identities[0].provider_type == app::IdentityProviderAnonymous;
}

std::string AppUser::device_id() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_app_data.device_id;
}

bool AppUser::has_device_id() const
{
    util::CheckedLockGuard lock(m_mutex);
    return !m_app_data.device_id.empty() && m_app_data.device_id != "000000000000000000000000";
}

AppUserProfile AppUser::user_profile() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_app_data.profile;
}

util::Optional<bson::BsonDocument> AppUser::custom_data() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_data.access_token.user_data;
}

// move to App
//app::MongoClient AppUser::mongo_client(const std::string& service_name)
//{
//    util::CheckedLockGuard lk(m_mutex);
//    REALM_ASSERT(m_data.state == UserState::LoggedIn);
//    return app::MongoClient(shared_from_this(), m_app, service_name);
//}

void AppUser::refresh_custom_data(util::UniqueFunction<void(util::Optional<app::AppError>)> completion_block)
    REQUIRES(!m_mutex)
{
    refresh_custom_data(false, std::move(completion_block));
}

void AppUser::refresh_custom_data(bool update_location,
                                   util::UniqueFunction<void(util::Optional<app::AppError>)> completion_block)
{
    std::shared_ptr<app::App> app;
    std::shared_ptr<AppUser> user;
    {
        util::CheckedLockGuard lk(m_mutex);
        if (m_data.state != UserState::Removed) {
            user = shared_from_this();
        }
        app = m_app;
    }
    if (!user) {
        completion_block(
            app::AppError(ErrorCodes::ClientUserNotFound,
                          util::format("Cannot initiate a refresh on user '%1' because the user has been removed", m_user_id)));
    }
    else {
        app->refresh_custom_data(user, update_location, std::move(completion_block));
    }
}
} // namespace realm

namespace std {
size_t hash<realm::AppUserIdentity>::operator()(const realm::AppUserIdentity& k) const
{
    return ((hash<string>()(k.id) ^ (hash<string>()(k.provider_type) << 1)) >> 1);
}
} // namespace std

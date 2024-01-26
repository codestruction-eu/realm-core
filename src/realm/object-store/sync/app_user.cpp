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

#include <realm/object-store/sync/app_user.hpp>

#include <realm/object-store/sync/app.hpp>
#include <realm/object-store/sync/app_credentials.hpp>
#include <realm/object-store/sync/generic_network_transport.hpp>
#include <realm/object-store/sync/impl/sync_metadata.hpp>
#include <realm/object-store/sync/mongo_client.hpp>

namespace realm::app {

SyncUserIdentity::SyncUserIdentity(const std::string& id, const std::string& provider_type)
    : id(id)
    , provider_type(provider_type)
{
}

static std::shared_ptr<app::App> lock_or_throw(std::weak_ptr<app::App> app)
{
    if (auto locked = app.lock()) {
        return locked;
    }
    throw RuntimeError(ErrorCodes::RuntimeError, "Invalid operation on user which has become detached.");
}

AppUser::AppUser(Private, std::string_view refresh_token, std::string_view id, std::string_view access_token,
                 std::string_view device_id, std::shared_ptr<app::App> app)
    : SyncUser(UserData{app->config().app_id, std::string(id), RealmJWT(access_token), RealmJWT(refresh_token),
                        State::LoggedIn},
               app)
    , m_device_id(device_id)
    , m_app(std::move(app))
{
    REALM_ASSERT(!access_token.empty() && !refresh_token.empty());

    lock_or_throw(m_app)->backing_store()->perform_metadata_update(
        [&](const auto& manager) NO_THREAD_SAFETY_ANALYSIS {
            auto metadata = manager.get_or_make_user_metadata(user_id());
            metadata->set_state_and_tokens(State::LoggedIn, access_token, refresh_token);
            metadata->set_device_id(m_device_id);
            m_legacy_identities = metadata->legacy_identities();
            this->m_user_profile = metadata->profile();
        });
}

AppUser::AppUser(Private, const SyncUserMetadata& data, std::shared_ptr<app::App> app)
    : SyncUser(UserData{app->config().app_id, data.identity(), RealmJWT(data.access_token()),
                        RealmJWT(data.refresh_token()), data.state()},
               app)
    , m_legacy_identities(data.legacy_identities())
    , m_user_identities(data.identities())
    , m_user_profile(data.profile())
    , m_device_id(data.device_id())
    , m_app(std::move(app))
{
    REALM_ASSERT(data.state() != State::LoggedIn || (!refresh_token().empty() && !access_token().empty()));
}

std::weak_ptr<app::App> AppUser::app() const
{
    if (state() == State::Removed) {
        throw app::AppError(
            ErrorCodes::ClientUserNotFound,
            util::format("Cannot start a sync session for user '%1' because this user has been removed.", user_id()));
    }
    return m_app;
}

void AppUser::detach_from_backing_store()
{
    m_app.reset();
}

std::vector<SyncUserIdentity> AppUser::identities() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_user_identities;
}

bool AppUser::is_anonymous() const
{
    util::CheckedLockGuard lock(m_mutex);
    return do_is_anonymous();
}

bool AppUser::do_is_anonymous() const
{
    return is_logged_in() && m_user_identities.size() == 1 &&
           m_user_identities[0].provider_type == app::IdentityProviderAnonymous;
}

std::string AppUser::device_id() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_device_id;
}

bool AppUser::has_device_id() const
{
    util::CheckedLockGuard lock(m_mutex);
    return !m_device_id.empty() && m_device_id != "000000000000000000000000";
}

SyncUserProfile AppUser::user_profile() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_user_profile;
}

util::Optional<bson::BsonDocument> AppUser::custom_data() const
{
    return data().access_token.user_data;
}

void AppUser::update_user_profile(std::vector<SyncUserIdentity> identities, SyncUserProfile profile)
{
    util::CheckedLockGuard lock(m_mutex);
    if (state() == SyncUser::State::Removed) {
        return;
    }

    m_user_identities = std::move(identities);
    m_user_profile = std::move(profile);

    lock_or_throw(m_app)->backing_store()->perform_metadata_update(
        [&](const auto& manager) NO_THREAD_SAFETY_ANALYSIS {
            auto metadata = manager.get_or_make_user_metadata(user_id());
            metadata->set_identities(m_user_identities);
            metadata->set_user_profile(m_user_profile);
        });
}

app::MongoClient AppUser::mongo_client(const std::string& service_name)
{
    util::CheckedLockGuard lk(m_mutex);
    REALM_ASSERT(state() == SyncUser::State::LoggedIn);
    return app::MongoClient(shared_from_this(), lock_or_throw(m_app), service_name);
}

} // namespace realm::app

namespace std {
size_t hash<realm::app::SyncUserIdentity>::operator()(const realm::app::SyncUserIdentity& k) const
{
    return ((hash<string>()(k.id) ^ (hash<string>()(k.provider_type) << 1)) >> 1);
}
} // namespace std

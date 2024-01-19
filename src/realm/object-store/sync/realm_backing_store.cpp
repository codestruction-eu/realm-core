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

#include <realm/object-store/sync/realm_backing_store.hpp>

#include <realm/object-store/sync/impl/sync_file.hpp>
#include <realm/object-store/sync/impl/sync_metadata.hpp>
#include <realm/object-store/sync/sync_user.hpp>

using namespace realm;
using namespace realm::app;

UserManager::UserManager(std::shared_ptr<App> app, SyncFileManager& file_manager,
                         BackingStore& backing_store)
: m_file_manager(file_manager)
, m_store(backing_store)
, m_app(app)
{
//    for (auto& data : m_store.get_logged_in_users()) {
//        m_users.push_back(AppUser::make(std::move(data), app));
//    }
}

UserManager::~UserManager()
{
    util::CheckedLockGuard lk(m_user_mutex);
    for (auto& user : m_users) {
        user->detach_from_backing_store();
    }
}

//void UserManager::reset_for_testing()
//{
//    {
//        // Destroy all the users.
//        util::CheckedLockGuard lock(m_user_mutex);
//        for (auto& user : m_users) {
//            user->detach_from_backing_store();
//        }
//        m_users.clear();
//        m_current_user = nullptr;
//    }
//    // FIXME: clearing disk state might be happening too soon?
//    {
//        util::CheckedLockGuard lock(m_file_system_mutex);
//        if (m_file_manager)
//            util::try_remove_dir_recursive(m_file_manager->base_path());
//        m_file_manager = nullptr;
//    }
//}

std::shared_ptr<AppUser> UserManager::get_user(std::string_view user_id, std::string_view refresh_token,
                                                std::string_view access_token, std::string_view device_id)
{
    m_store.create_user(user_id, refresh_token, access_token, device_id);
    std::shared_ptr<UserProvider> provider;

    util::CheckedLockGuard lock(m_user_mutex);
    auto it = std::find_if(m_users.begin(), m_users.end(), [&](const auto& user) {
        return user->user_id() == user_id && user->state() != UserState::Removed;
    });
    if (it != m_users.end()) {
        return *it;
    }
    auto user = AppUser::make(m_app.lock(), user_id);
    m_users.emplace(m_users.begin(), user);
    return user;
}

std::vector<std::shared_ptr<AppUser>> UserManager::all_users()
{
    util::CheckedLockGuard lock(m_user_mutex);
    m_users.erase(std::remove_if(m_users.begin(), m_users.end(),
                                 [](auto& user) {
                                     if (user->state() == UserState::Removed) {
                                         user->detach_from_backing_store();
                                         return true;
                                     }
        return false;
                                 }),
                  m_users.end());
    return m_users;
}

std::shared_ptr<AppUser> UserManager::get_user_for_id(std::string_view user_id) const noexcept
{
    auto is_active_user = [user_id](auto& el) {
        return el->user_id() == user_id;
    };
    auto it = std::find_if(m_users.begin(), m_users.end(), is_active_user);
    return it == m_users.end() ? nullptr : *it;
}

std::shared_ptr<AppUser> UserManager::get_current_user()
{
    util::CheckedLockGuard lock(m_user_mutex);
    if (!m_current_user) {
        if (auto cur_user_ident = m_store.get_current_user(); !cur_user_ident.empty()) {
            m_current_user = get_user_for_id(cur_user_ident);
        }
    }
    return m_current_user;
}

void UserManager::log_out_user(AppUser& user, bool is_anonymous)
{
    // Anonymous users cannot log back in, so set them to removed rather than logged out
    if (is_anonymous) {
        return remove_user(user);
    }

    util::CheckedLockGuard lock(m_user_mutex);

    // Move this user to the end of the vector
    auto user_pos = std::partition(m_users.begin(), m_users.end(), [&](auto& u) {
        return u.get() != &user;
    });

    auto new_active_pos = std::find_if(m_users.begin(), user_pos, [](auto& u) {
        return u->state() == UserState::LoggedIn;
    });
    auto new_active = new_active_pos == user_pos ? "" : (*new_active_pos)->user_id();

    m_store.log_out(user.user_id(), new_active, UserState::LoggedOut);
}

void UserManager::remove_user(AppUser& user, bool delete_immediately)
{
    // user may no longer be safe to use after we remove it from m_users, so
    // read what we need from it first
    std::string user_id = user.user_id();
    user.detach_from_backing_store();

    util::CheckedLockGuard lock(m_user_mutex);
    auto it = std::find_if(m_users.begin(), m_users.end(), [&](auto& u) {
        return u.get() == &user;
    });
    REALM_ASSERT(it != m_users.end());
    m_users.erase(it);

    auto new_active_pos = std::find_if(m_users.begin(), m_users.end(), [](auto& u) {
        return u->state() == UserState::LoggedIn;
    });
    auto new_active = new_active_pos == m_users.end() ? "" : (*new_active_pos)->user_id();

    if (delete_immediately) {
        m_store.log_out(user_id, new_active, UserState::Removed);
    }
    else {
        m_store.delete_user(m_file_manager, user_id, new_active);
    }
}

void UserManager::remove_user(AppUser& user)
{
    remove_user(user, false);
}

void UserManager::delete_user(AppUser& user)
{
    remove_user(user, true);
}

void UserManager::set_current_user(const std::shared_ptr<AppUser>& user)
{
    {
        util::CheckedLockGuard lock(m_user_mutex);
        m_current_user = user;
    }
    m_store.set_current_user(user->user_id());
}

std::shared_ptr<AppUser> UserManager::get_existing_logged_in_user(std::string_view user_id) const
{
    util::CheckedLockGuard lock(m_user_mutex);
    auto user = get_user_for_id(user_id);
    return user && user->state() == UserState::LoggedIn ? user : nullptr;
}

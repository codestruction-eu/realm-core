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

#include <realm/object-store/sync/sync_manager.hpp>

#include <realm/object-store/sync/impl/sync_client.hpp>
#include <realm/object-store/sync/impl/sync_file.hpp>
#include <realm/object-store/sync/app_backing_store.hpp>
#include <realm/object-store/sync/sync_session.hpp>
#include <realm/object-store/sync/sync_user.hpp>
#include <realm/object-store/sync/app.hpp>
#include <realm/object-store/util/uuid.hpp>

#include <realm/util/sha_crypto.hpp>
#include <realm/util/hex_dump.hpp>

#include <realm/exceptions.hpp>

using namespace realm;
using namespace realm::_impl;

app::SyncClientTimeouts::SyncClientTimeouts()
    : connect_timeout(sync::Client::default_connect_timeout)
    , connection_linger_time(sync::Client::default_connection_linger_time)
    , ping_keepalive_period(sync::Client::default_ping_keepalive_period)
    , pong_keepalive_timeout(sync::Client::default_pong_keepalive_timeout)
    , fast_reconnect_limit(sync::Client::default_fast_reconnect_limit)
{
}

SyncManager::SyncManager(const app::SyncClientConfig& config, app::BackingStore& backing_store, SyncFileManager& file_manager)
: m_backing_store(backing_store)
, m_file_manager(file_manager)
, m_config(config)
{
    // create a new logger - if the logger_factory is updated later, a new
    // logger will be created at that time.
    do_make_logger();
}

void SyncManager::reset_for_testing()
{
    {
        util::CheckedLockGuard lock(m_mutex);
        // Stop the client. This will abort any uploads that inactive sessions are waiting for.
        if (m_sync_client)
            m_sync_client->stop();
    }

    {
        util::CheckedUniqueLock lock(m_session_mutex);

        bool no_sessions = !do_has_existing_sessions();
        // There's a race between this function and sessions tearing themselves down waiting for m_session_mutex.
        // So we give up to a 5 second grace period for any sessions being torn down to unregister themselves.
        auto since_poll_start = [start = std::chrono::steady_clock::now()] {
            return std::chrono::steady_clock::now() - start;
        };
        for (; !no_sessions && since_poll_start() < std::chrono::seconds(5);
             no_sessions = !do_has_existing_sessions()) {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            lock.lock();
        }
        // Callers of `SyncManager::reset_for_testing` should ensure there are no existing sessions
        // prior to calling `reset_for_testing`.
        if (!no_sessions) {
            util::CheckedLockGuard lock(m_mutex);
            for (auto session : m_sessions) {
                m_logger_ptr->error("open session at path '%1'", session.first);
            }
        }
        REALM_ASSERT_RELEASE(no_sessions);

        // Destroy any inactive sessions.
        // FIXME: We shouldn't have any inactive sessions at this point! Sessions are expected to
        // remain inactive until their final upload completes, at which point they are unregistered
        // and destroyed. Our call to `sync::Client::stop` above aborts all uploads, so all sessions
        // should have already been destroyed.
        m_sessions.clear();
    }

    {
        util::CheckedLockGuard lock(m_mutex);
        // Destroy the client now that we have no remaining sessions.
        m_sync_client = nullptr;

        // Reset even more state.
        m_config = {};
        m_logger_ptr.reset();
        m_sync_route = "";
    }
}

void SyncManager::set_log_level(util::Logger::Level level) noexcept
{
    util::CheckedLockGuard lock(m_mutex);
    m_config.log_level = level;
    // Update the level threshold in the already created logger
    if (m_logger_ptr) {
        m_logger_ptr->set_level_threshold(level);
    }
}

void SyncManager::set_logger_factory(app::SyncClientConfig::LoggerFactory factory)
{
    util::CheckedLockGuard lock(m_mutex);
    m_config.logger_factory = std::move(factory);

    if (m_sync_client)
        throw LogicError(ErrorCodes::IllegalOperation,
                         "Cannot set the logger factory after creating the sync client");

    // Create a new logger using the new factory
    do_make_logger();
}

void SyncManager::do_make_logger()
{
    if (m_config.logger_factory) {
        m_logger_ptr = m_config.logger_factory(m_config.log_level);
    }
    else {
        m_logger_ptr = util::Logger::get_default_logger();
    }
}

const std::shared_ptr<util::Logger>& SyncManager::get_logger() const
{
    util::CheckedLockGuard lock(m_mutex);
    return m_logger_ptr;
}

void SyncManager::set_user_agent(std::string user_agent)
{
    util::CheckedLockGuard lock(m_mutex);
    m_config.user_agent_application_info = std::move(user_agent);
}

void SyncManager::set_timeouts(app::SyncClientTimeouts timeouts)
{
    util::CheckedLockGuard lock(m_mutex);
    m_config.timeouts = timeouts;
}

void SyncManager::reconnect() const
{
    util::CheckedLockGuard lock(m_session_mutex);
    for (auto& it : m_sessions) {
        it.second->handle_reconnect();
    }
}

util::Logger::Level SyncManager::log_level() const noexcept
{
    util::CheckedLockGuard lock(m_mutex);
    return m_config.log_level;
}

SyncManager::~SyncManager() NO_THREAD_SAFETY_ANALYSIS
{
    // Grab the current sessions under a lock so we can shut them down. We have to
    // release the lock before calling them as shutdown_and_wait() will call
    // back into us.
    decltype(m_sessions) current_sessions;
    {
        util::CheckedLockGuard lk(m_session_mutex);
        m_sessions.swap(current_sessions);
    }

    for (auto& [_, session] : current_sessions) {
        session->detach_from_sync_manager();
    }

    {
        util::CheckedLockGuard lk(m_mutex);
        // Stop the client. This will abort any uploads that inactive sessions are waiting for.
        if (m_sync_client)
            m_sync_client->stop();
    }
}

struct UnsupportedBsonPartition : public std::logic_error {
    UnsupportedBsonPartition(std::string msg)
        : std::logic_error(msg)
    {
    }
};

static std::string string_from_partition(std::string_view partition)
{
    bson::Bson partition_value = bson::parse(partition);
    switch (partition_value.type()) {
        case bson::Bson::Type::Int32:
            return util::format("i_%1", static_cast<int32_t>(partition_value));
        case bson::Bson::Type::Int64:
            return util::format("l_%1", static_cast<int64_t>(partition_value));
        case bson::Bson::Type::String:
            return util::format("s_%1", static_cast<std::string>(partition_value));
        case bson::Bson::Type::ObjectId:
            return util::format("o_%1", static_cast<ObjectId>(partition_value).to_string());
        case bson::Bson::Type::Uuid:
            return util::format("u_%1", static_cast<UUID>(partition_value).to_string());
        case bson::Bson::Type::Null:
            return "null";
        default:
            throw UnsupportedBsonPartition(util::format("Unsupported partition key value: '%1'. Only int, string "
                                                        "UUID and ObjectId types are currently supported.",
                                                        partition_value.to_string()));
    }
}


std::string SyncManager::path_for_realm(const SyncConfig& config, util::Optional<std::string> custom_file_name) const
{
    auto user = config.user;
    REALM_ASSERT(user);
    // Attempt to make a nicer filename which will ease debugging when
    // locating files in the filesystem.
    auto file_name = [&]() -> std::string {
        if (custom_file_name) {
            return *custom_file_name;
        }
        if (config.flx_sync_requested) {
            REALM_ASSERT_DEBUG(config.partition_value.empty());
            return "flx_sync_default";
        }
        return string_from_partition(config.partition_value);
    }();
    auto path = m_file_manager.realm_file_path(user->user_id(), user->legacy_identities(), file_name,
                                                config.partition_value);
    m_backing_store.add_realm_path(user->user_id(), path);
    return path;
}

std::string SyncManager::audit_path_root(const SyncUser& user, std::string_view app_id,
                                         std::string_view partition_prefix) const
{
#ifdef _WIN32 // Move to File?
    const char separator[] = "\\";
#else
    const char separator[] = "/";
#endif

    // "$root/realm-audit/$appId/$userId/$partitonPrefix/"
//    return util::format("%2%1realm-audit%1%3%1%4%1%5%1", separator, m_config.base_file_path, app_id, user.user_id(), partition_prefix);
    return "";
}

std::vector<std::shared_ptr<SyncSession>> SyncManager::get_all_sessions() const
{
    util::CheckedLockGuard lock(m_session_mutex);
    std::vector<std::shared_ptr<SyncSession>> sessions;
    for (auto& [_, session] : m_sessions) {
        if (auto external_reference = session->existing_external_reference())
            sessions.push_back(std::move(external_reference));
    }
    return sessions;
}

std::vector<std::shared_ptr<SyncSession>> SyncManager::get_all_sessions_for(const SyncUser& user) const
{
    util::CheckedLockGuard lock(m_session_mutex);
    std::vector<std::shared_ptr<SyncSession>> sessions;
    for (auto& [_, session] : m_sessions) {
        if (session->user().get() == &user) {
            if (auto external_reference = session->existing_external_reference())
                sessions.push_back(std::move(external_reference));
        }
    }
    return sessions;
}

std::shared_ptr<SyncSession> SyncManager::get_existing_active_session(const std::string& path) const
{
    util::CheckedLockGuard lock(m_session_mutex);
    if (auto session = get_existing_session_locked(path)) {
        if (auto external_reference = session->existing_external_reference())
            return external_reference;
    }
    return nullptr;
}

std::shared_ptr<SyncSession> SyncManager::get_existing_session_locked(const std::string& path) const
{
    auto it = m_sessions.find(path);
    return it == m_sessions.end() ? nullptr : it->second;
}

std::shared_ptr<SyncSession> SyncManager::get_existing_session(const std::string& path) const
{
    util::CheckedLockGuard lock(m_session_mutex);
    if (auto session = get_existing_session_locked(path))
        return session->external_reference();

    return nullptr;
}

std::shared_ptr<SyncSession> SyncManager::get_session(std::shared_ptr<DB> db, const RealmConfig& config)
{
    auto& client = get_sync_client(); // Throws
#ifndef __EMSCRIPTEN__
    auto path = db->get_path();
    REALM_ASSERT_EX(path == config.path, path, config.path);
#else
    auto path = config.path;
#endif
    REALM_ASSERT(config.sync_config);

    util::CheckedUniqueLock lock(m_session_mutex);
    if (auto session = get_existing_session_locked(path)) {
        return session->external_reference();
    }

    auto shared_session = SyncSession::create(client, std::move(db), config, this);
    m_sessions[path] = shared_session;

    // Create the external reference immediately to ensure that the session will become
    // inactive if an exception is thrown in the following code.
    return shared_session->external_reference();
}

bool SyncManager::has_existing_sessions()
{
    util::CheckedLockGuard lock(m_session_mutex);
    return do_has_existing_sessions();
}

bool SyncManager::do_has_existing_sessions()
{
    return std::any_of(m_sessions.begin(), m_sessions.end(), [](auto& element) {
        return element.second->existing_external_reference();
    });
}

void SyncManager::wait_for_sessions_to_terminate()
{
    auto& client = get_sync_client(); // Throws
    client.wait_for_session_terminations();
}

void SyncManager::unregister_session(const std::string& path)
{
    util::CheckedUniqueLock lock(m_session_mutex);
    auto it = m_sessions.find(path);
    if (it == m_sessions.end()) {
        // The session may already be unregistered. This always happens in the
        // SyncManager destructor, and can also happen due to multiple threads
        // tearing things down at once.
        return;
    }

    // Sync session teardown calls this function, so we need to be careful with
    // locking here. We need to unlock `m_session_mutex` before we do anything
    // which could result in a re-entrant call or we'll deadlock, which in this
    // function means unlocking before we destroy a `shared_ptr<SyncSession>`
    // (either the external reference or internal reference versions).
    // The external reference version will only be the final reference if
    // another thread drops a reference while we're in this function.
    // Dropping the final internal reference does not appear to ever actually
    // result in a recursive call to this function at the time this comment was
    // written, but releasing the lock in that case as well is still safer.

    if (auto existing_session = it->second->existing_external_reference()) {
        // We got here because the session entered the inactive state, but
        // there's still someone referencing it so we should leave it be. This
        // can happen if the user was logged out, or if all Realms using the
        // session were destroyed but the SDK user is holding onto the session.

        // Explicit unlock so that `existing_session`'s destructor runs after
        // the unlock for the reasons noted above
        lock.unlock();
        return;
    }

    // Remove the session from the map while holding the lock, but then defer
    // destroying it until after we unlock the mutex for the reasons noted above.
    auto session = m_sessions.extract(it);
    lock.unlock();
}

void SyncManager::set_session_multiplexing(bool allowed)
{
    util::CheckedLockGuard lock(m_mutex);
    if (m_config.multiplex_sessions == allowed)
        return; // Already enabled, we can ignore

    if (m_sync_client)
        throw LogicError(ErrorCodes::IllegalOperation,
                         "Cannot enable session multiplexing after creating the sync client");

    m_config.multiplex_sessions = allowed;
}

SyncClient& SyncManager::get_sync_client() const
{
    util::CheckedLockGuard lock(m_mutex);
    if (!m_sync_client)
        m_sync_client = create_sync_client(); // Throws
    return *m_sync_client;
}

std::unique_ptr<SyncClient> SyncManager::create_sync_client() const
{
    return std::make_unique<SyncClient>(m_logger_ptr, m_config);
}

void SyncManager::close_all_sessions()
{
    // log_out() will call unregister_session(), which requires m_session_mutex,
    // so we need to iterate over them without holding the lock.
    decltype(m_sessions) sessions;
    {
        util::CheckedLockGuard lk(m_session_mutex);
        m_sessions.swap(sessions);
    }

    for (auto& [_, session] : sessions) {
        session->force_close();
    }

    get_sync_client().wait_for_session_terminations();
}

void SyncManager::OnlyForTesting::voluntary_disconnect_all_connections(SyncManager& mgr)
{
    mgr.get_sync_client().voluntary_disconnect_all_connections();
}

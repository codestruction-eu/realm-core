////////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or utilied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#include <realm/object-store/sync/app.hpp>

#include <realm/sync/network/http.hpp>
#include <realm/util/base64.hpp>
#include <realm/util/flat_map.hpp>
#include <realm/util/platform_info.hpp>
#include <realm/util/uri.hpp>
#include <realm/object-store/sync/app_user.hpp>
#include <realm/object-store/sync/app_utils.hpp>
#include <realm/object-store/sync/impl/app_metadata.hpp>
#include <realm/object-store/sync/impl/sync_file.hpp>
#include <realm/object-store/sync/sync_manager.hpp>
#include <realm/object-store/sync/sync_user.hpp>

#ifdef __EMSCRIPTEN__
#include <realm/object-store/sync/impl/emscripten/network_transport.hpp>
#endif

#include <external/json/json.hpp>
#include <sstream>
#include <string>

using namespace realm;
using namespace realm::app;
using namespace bson;
using util::Optional;
using util::UniqueFunction;

namespace {
// MARK: - Helpers

REALM_COLD
REALM_NOINLINE
REALM_NORETURN
void throw_json_error(ErrorCodes::Error ec, std::string_view message)
{
    throw AppError(ec, std::string(message));
}

template <typename T>
T as(const Bson& bson)
{
    if (holds_alternative<T>(bson)) {
        return static_cast<T>(bson);
    }
    throw_json_error(ErrorCodes::MalformedJson, "?");
}

template <typename T>
T get(const BsonDocument& doc, const std::string& key)
{
    auto& raw = doc.entries();
    if (auto it = raw.find(key); it != raw.end()) {
        return as<T>(it->second);
    }
    throw_json_error(ErrorCodes::MissingJsonKey, key);
    return {};
}

template <typename T>
void read_field(const BsonDocument& data, const std::string& key, T& value)
{
    auto& raw = data.entries();
    if (auto it = raw.find(key); it != raw.end()) {
        value = as<T>(it->second);
    }
    else {
        throw_json_error(ErrorCodes::MissingJsonKey, key);
    }
}

template <>
void read_field(const BsonDocument& data, const std::string& key, ObjectId& value)
{
    value = ObjectId(get<std::string>(data, key).c_str());
}

template <typename T>
void read_field(const BsonDocument& data, const std::string& key, Optional<T>& value)
{
    auto& raw = data.entries();
    if (auto it = raw.find(key); it != raw.end()) {
        value = as<T>(it->second);
    }
}

template <typename T>
T parse(std::string_view str)
{
    try {
        return as<T>(bson::parse(str));
    }
    catch (const std::exception& e) {
        throw_json_error(ErrorCodes::MalformedJson, e.what());
    }
}

struct UserAPIKeyResponseHandler {
    UniqueFunction<void(App::UserAPIKey&&, Optional<AppError>)> completion;
    void operator()(const Response& response)
    {
        if (auto error = AppUtils::check_for_errors(response)) {
            return completion({}, std::move(error));
        }

        try {
            auto json = parse<BsonDocument>(response.body);
            completion(read_user_api_key(json), {});
        }
        catch (AppError& e) {
            completion({}, std::move(e));
        }
    }

    static App::UserAPIKey read_user_api_key(const BsonDocument& doc)
    {
        App::UserAPIKey user_api_key;
        read_field(doc, "_id", user_api_key.id);
        read_field(doc, "key", user_api_key.key);
        read_field(doc, "name", user_api_key.name);
        read_field(doc, "disabled", user_api_key.disabled);
        return user_api_key;
    }
};

enum class RequestTokenType { NoAuth, AccessToken, RefreshToken };

// generate the request headers for a HTTP call, by default it will generate headers with a refresh token if a user is
// passed
HttpHeaders get_request_headers(const std::shared_ptr<User>& with_user_authorization = nullptr,
                                RequestTokenType token_type = RequestTokenType::RefreshToken)
{
    HttpHeaders headers{{"Content-Type", "application/json;charset=utf-8"}, {"Accept", "application/json"}};

    if (with_user_authorization) {
        switch (token_type) {
            case RequestTokenType::NoAuth:
                break;
            case RequestTokenType::AccessToken:
                headers.insert({"Authorization", util::format("Bearer %1", with_user_authorization->access_token())});
                break;
            case RequestTokenType::RefreshToken:
                headers.insert(
                    {"Authorization", util::format("Bearer %1", with_user_authorization->refresh_token())});
                break;
        }
    }
    return headers;
}

UniqueFunction<void(const Response&)> handle_default_response(UniqueFunction<void(Optional<AppError>)>&& completion)
{
    return [completion = std::move(completion)](const Response& response) {
        completion(AppUtils::check_for_errors(response));
    };
}

constexpr static std::string_view s_default_base_url = "https://realm.mongodb.com";
constexpr static std::string_view s_base_path = "/api/client/v2.0";
constexpr static std::string_view s_app_path = "/app";
constexpr static std::string_view s_auth_path = "/auth";
constexpr static std::string_view s_sync_path = "/realm-sync";
constexpr static uint64_t s_default_timeout_ms = 60000;
constexpr static std::string_view s_username_password_provider_key = "local-userpass";
constexpr static std::string_view s_user_api_key_provider_key_path = "api_keys";
constexpr static int s_max_http_redirects = 20;
static util::FlatMap<std::string, util::FlatMap<std::string, SharedApp>> s_apps_cache; // app_id -> base_url -> app
std::mutex s_apps_mutex;
} // anonymous namespace

namespace realm {
namespace app {
// NO_THREAD_SAFETY_ANALYSIS because clang generates a false positive.
// "Calling function configure requires negative capability '!app->m_route_mutex'"
// But 'app' is an object just created in this static method so it is not possible to annotate this in the header.
SharedApp App::get_app(CacheMode mode, const AppConfig& config) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode == CacheMode::Enabled) {
        std::lock_guard lock(s_apps_mutex);
        auto& app = s_apps_cache[config.app_id][config.base_url.value_or(std::string(s_default_base_url))];
        if (!app) {
            app = std::make_shared<App>(Private(), config);
        }
        return app;
    }
    REALM_ASSERT(mode == CacheMode::Disabled);
    return std::make_shared<App>(Private(), config);
}

SharedApp App::get_cached_app(const std::string& app_id, const std::optional<std::string>& base_url)
{
    std::lock_guard lock(s_apps_mutex);
    if (auto it = s_apps_cache.find(app_id); it != s_apps_cache.end()) {
        const auto& apps_by_url = it->second;

        auto app_it = base_url ? apps_by_url.find(*base_url) : apps_by_url.begin();
        if (app_it != apps_by_url.end()) {
            return app_it->second;
        }
    }

    return nullptr;
}

void App::clear_cached_apps()
{
    std::lock_guard lock(s_apps_mutex);
    s_apps_cache.clear();
}

void App::close_all_sync_sessions()
{
    std::lock_guard lock(s_apps_mutex);
    for (auto& apps_by_url : s_apps_cache) {
        for (auto& app : apps_by_url.second) {
            app.second->sync_manager()->close_all_sessions();
        }
    }
}

App::App(Private, const AppConfig& config)
    : m_config(config)
    , m_base_url(m_config.base_url.value_or(std::string(s_default_base_url)))
    , m_request_timeout_ms(m_config.default_request_timeout_ms.value_or(s_default_timeout_ms))
    , m_file_manager(std::make_unique<SyncFileManager>(config))
    , m_metadata_store(create_metadata_store(config, *m_file_manager))
    , m_sync_manager(SyncManager::create(config.sync_client_config))
{
#ifdef __EMSCRIPTEN__
    if (!m_config.transport) {
        m_config.transport = std::make_shared<_impl::EmscriptenNetworkTransport>();
    }
#endif
    REALM_ASSERT(m_config.transport);

    // if a base url is provided, then verify the value
    if (m_config.base_url) {
        if (auto comp = AppUtils::split_url(*m_config.base_url); !comp.is_ok()) {
            throw Exception(comp.get_status());
        }
    }
    // Setup a baseline set of routes using the provided or default base url
    // These will be updated when the location info is refreshed prior to sending the
    // first AppServices HTTP request.
    configure_route(m_base_url, m_base_url);

    if (m_config.device_info.platform_version.empty()) {
        throw InvalidArgument("You must specify the Platform Version in App::Config::device_info");
    }

    if (m_config.device_info.sdk.empty()) {
        throw InvalidArgument("You must specify the SDK Name in App::Config::device_info");
    }

    if (m_config.device_info.sdk_version.empty()) {
        throw InvalidArgument("You must specify the SDK Version in App::Config::device_info");
    }
}

App::~App() {}

bool App::init_logger()
{
    if (!m_logger_ptr) {
        m_logger_ptr = m_sync_manager->get_logger();
        if (!m_logger_ptr) {
            m_logger_ptr = util::Logger::get_default_logger();
        }
    }
    return bool(m_logger_ptr);
}

bool App::would_log(util::Logger::Level level)
{
    return init_logger() && m_logger_ptr->would_log(level);
}

template <class... Params>
void App::log_debug(const char* message, Params&&... params)
{
    if (init_logger()) {
        m_logger_ptr->log(util::Logger::Level::debug, message, std::forward<Params>(params)...);
    }
}

template <class... Params>
void App::log_error(const char* message, Params&&... params)
{
    if (init_logger()) {
        m_logger_ptr->log(util::Logger::Level::error, message, std::forward<Params>(params)...);
    }
}

std::string App::auth_route()
{
    util::CheckedLockGuard guard(m_route_mutex);
    return m_auth_route;
}

std::string App::base_url()
{
    util::CheckedLockGuard guard(m_route_mutex);
    return m_base_url;
}

std::string App::get_host_url()
{
    util::CheckedLockGuard guard(m_route_mutex);
    return m_host_url;
}

std::string App::get_ws_host_url()
{
    util::CheckedLockGuard guard(m_route_mutex);
    return m_ws_host_url;
}

std::string App::make_sync_route(Optional<std::string> ws_host_url)
{
    return util::format("%1%2%3/%4%5", ws_host_url.value_or(m_ws_host_url), s_base_path, s_app_path, m_config.app_id,
                        s_sync_path);
}

void App::configure_route(const std::string& host_url, const std::string& ws_host_url)
{
    m_host_url = host_url;
    m_ws_host_url = ws_host_url;

    if (m_ws_host_url.find("http") == 0) {
        m_ws_host_url.replace(0, 4, "ws");
    }

    // host_url is the url to the server: e.g., https://realm.mongodb.com or https://localhost:9090
    // base_route is the baseline client api path: e.g. https://realm.mongodb.com/api/client/v2.0
    m_base_route = util::format("%1%2", m_host_url, s_base_path);
    // app_route is the cloud app URL: https://realm.mongodb.com/api/client/v2.0/app/<app_id>
    m_app_route = util::format("%1%2/%3", m_base_route, s_app_path, m_config.app_id);
    // auth_route is cloud app auth URL: https://realm.mongodb.com/api/client/v2.0/app/<app_id>/auth
    m_auth_route = util::format("%1%2", m_app_route, s_auth_path);
}

void App::update_hostname(const std::string& host_url, const std::optional<std::string>& ws_host_url,
                          const std::optional<std::string>& new_base_url)
{
    // Update url components based on new hostname (and optional websocket hostname) values
    log_debug("App: update_hostname: %1%2%3", host_url, ws_host_url ? util::format(" | %1", *ws_host_url) : "",
              new_base_url ? util::format(" | base URL: %1", *new_base_url) : "");
    // Save the new base url, if provided
    if (new_base_url) {
        m_base_url = *new_base_url;
    }
    // If a new host url was returned from the server, use it to configure the routes
    // Otherwise, use the m_base_url value
    std::string base_url = host_url.length() > 0 ? host_url : m_base_url;
    configure_route(base_url, ws_host_url.value_or(base_url));
}

// MARK: - Template specializations

template <>
App::UsernamePasswordProviderClient App::provider_client<App::UsernamePasswordProviderClient>()
{
    return App::UsernamePasswordProviderClient(shared_from_this());
}

template <>
App::UserAPIKeyProviderClient App::provider_client<App::UserAPIKeyProviderClient>()
{
    return App::UserAPIKeyProviderClient(*this);
}

// MARK: - UsernamePasswordProviderClient

void App::UsernamePasswordProviderClient::register_email(const std::string& email, const std::string& password,
                                                         UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: register_email: %1", email);
    m_parent->post(util::format("%1/providers/%2/register", m_parent->auth_route(), s_username_password_provider_key),
                   std::move(completion), {{"email", email}, {"password", password}});
}

void App::UsernamePasswordProviderClient::confirm_user(const std::string& token, const std::string& token_id,
                                                       UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: confirm_user");
    m_parent->post(util::format("%1/providers/%2/confirm", m_parent->auth_route(), s_username_password_provider_key),
                   std::move(completion), {{"token", token}, {"tokenId", token_id}});
}

void App::UsernamePasswordProviderClient::resend_confirmation_email(
    const std::string& email, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: resend_confirmation_email: %1", email);
    m_parent->post(
        util::format("%1/providers/%2/confirm/send", m_parent->auth_route(), s_username_password_provider_key),
        std::move(completion), {{"email", email}});
}

void App::UsernamePasswordProviderClient::retry_custom_confirmation(
    const std::string& email, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: retry_custom_confirmation: %1", email);
    m_parent->post(
        util::format("%1/providers/%2/confirm/call", m_parent->auth_route(), s_username_password_provider_key),
        std::move(completion), {{"email", email}});
}

void App::UsernamePasswordProviderClient::send_reset_password_email(
    const std::string& email, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: send_reset_password_email: %1", email);
    m_parent->post(
        util::format("%1/providers/%2/reset/send", m_parent->auth_route(), s_username_password_provider_key),
        std::move(completion), {{"email", email}});
}

void App::UsernamePasswordProviderClient::reset_password(const std::string& password, const std::string& token,
                                                         const std::string& token_id,
                                                         UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: reset_password");
    m_parent->post(util::format("%1/providers/%2/reset", m_parent->auth_route(), s_username_password_provider_key),
                   std::move(completion), {{"password", password}, {"token", token}, {"tokenId", token_id}});
}

void App::UsernamePasswordProviderClient::call_reset_password_function(
    const std::string& email, const std::string& password, const BsonArray& args,
    UniqueFunction<void(Optional<AppError>)>&& completion)
{
    m_parent->log_debug("App: call_reset_password_function: %1", email);
    m_parent->post(
        util::format("%1/providers/%2/reset/call", m_parent->auth_route(), s_username_password_provider_key),
        std::move(completion), {{"email", email}, {"password", password}, {"arguments", args}});
}

// MARK: - UserAPIKeyProviderClient

std::string App::UserAPIKeyProviderClient::url_for_path(const std::string& path = "") const
{
    if (!path.empty()) {
        return m_auth_request_client.url_for_path(
            util::format("%1/%2/%3", s_auth_path, s_user_api_key_provider_key_path, path));
    }

    return m_auth_request_client.url_for_path(util::format("%1/%2", s_auth_path, s_user_api_key_provider_key_path));
}

void App::UserAPIKeyProviderClient::create_api_key(
    const std::string& name, const std::shared_ptr<User>& user,
    UniqueFunction<void(UserAPIKey&&, Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::post;
    req.url = url_for_path();
    req.body = Bson(BsonDocument{{"name", name}}).to_string();
    req.uses_refresh_token = true;
    m_auth_request_client.do_authenticated_request(std::move(req), user,
                                                   UserAPIKeyResponseHandler{std::move(completion)});
}

void App::UserAPIKeyProviderClient::fetch_api_key(const realm::ObjectId& id, const std::shared_ptr<User>& user,
                                                  UniqueFunction<void(UserAPIKey&&, Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::get;
    req.url = url_for_path(id.to_string());
    req.uses_refresh_token = true;
    m_auth_request_client.do_authenticated_request(std::move(req), user,
                                                   UserAPIKeyResponseHandler{std::move(completion)});
}

void App::UserAPIKeyProviderClient::fetch_api_keys(
    const std::shared_ptr<User>& user,
    UniqueFunction<void(std::vector<UserAPIKey>&&, Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::get;
    req.url = url_for_path();
    req.uses_refresh_token = true;

    m_auth_request_client.do_authenticated_request(
        std::move(req), user, [completion = std::move(completion)](const Response& response) {
            if (auto error = AppUtils::check_for_errors(response)) {
                return completion({}, std::move(error));
            }

            try {
                auto json = parse<BsonArray>(response.body);
                std::vector<UserAPIKey> keys;
                keys.reserve(json.size());
                for (auto&& api_key_json : json) {
                    keys.push_back(UserAPIKeyResponseHandler::read_user_api_key(as<BsonDocument>(api_key_json)));
                }
                return completion(std::move(keys), {});
            }
            catch (AppError& e) {
                completion({}, std::move(e));
            }
        });
}

void App::UserAPIKeyProviderClient::delete_api_key(const realm::ObjectId& id, const std::shared_ptr<User>& user,
                                                   UniqueFunction<void(Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::del;
    req.url = url_for_path(id.to_string());
    req.uses_refresh_token = true;
    m_auth_request_client.do_authenticated_request(std::move(req), user,
                                                   handle_default_response(std::move(completion)));
}

void App::UserAPIKeyProviderClient::enable_api_key(const realm::ObjectId& id, const std::shared_ptr<User>& user,
                                                   UniqueFunction<void(Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::put;
    req.url = url_for_path(util::format("%1/enable", id.to_string()));
    req.uses_refresh_token = true;
    m_auth_request_client.do_authenticated_request(std::move(req), user,
                                                   handle_default_response(std::move(completion)));
}

void App::UserAPIKeyProviderClient::disable_api_key(const realm::ObjectId& id, const std::shared_ptr<User>& user,
                                                    UniqueFunction<void(Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::put;
    req.url = url_for_path(util::format("%1/disable", id.to_string()));
    req.uses_refresh_token = true;
    m_auth_request_client.do_authenticated_request(std::move(req), user,
                                                   handle_default_response(std::move(completion)));
}
// MARK: - App

std::shared_ptr<User> App::get_user_for_id(const std::string& user_id)
{
    if (auto& user = m_users[user_id]) {
        return user->shared_from_this();
    }
    return User::make(shared_from_this(), user_id);
}

void App::user_data_updated(const std::string& user_id)
{
    if (auto it = m_users.find(user_id); it != m_users.end()) {
        it->second->update_backing_data(m_metadata_store->get_user(user_id));
    }
}

std::shared_ptr<User> App::current_user()
{
    util::CheckedLockGuard lock(m_user_mutex);
    if (auto locked = m_current_user.lock(); locked && locked->is_logged_in())
        return locked;
    if (auto user_id = m_metadata_store->get_current_user(); !user_id.empty()) {
        auto user = get_user_for_id(user_id);
        m_current_user = user;
        return user;
    }
    return nullptr;
}

std::shared_ptr<User> App::get_existing_logged_in_user(std::string_view user_id)
{
    util::CheckedLockGuard lock(m_user_mutex);
    if (auto it = m_users.find(std::string(user_id)); it != m_users.end() && it->second->is_logged_in()) {
        return it->second->shared_from_this();
    }
    if (m_metadata_store->has_logged_in_user(user_id)) {
        return User::make(shared_from_this(), user_id);
    }
    return nullptr;
}

std::string App::get_base_url() const
{
    util::CheckedLockGuard guard(m_route_mutex);
    return m_base_url;
}

void App::update_base_url(std::optional<std::string> base_url, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    std::string new_base_url = base_url.value_or(std::string(s_default_base_url));

    if (new_base_url.empty()) {
        // Treat an empty string the same as requesting the default base url
        new_base_url = s_default_base_url;
        log_debug("App::update_base_url: empty => %1", new_base_url);
    }
    else {
        log_debug("App::update_base_url: %1", new_base_url);
    }

    // Validate the new base_url
    if (auto comp = AppUtils::split_url(new_base_url); !comp.is_ok()) {
        throw Exception(comp.get_status());
    }

    bool update_not_needed;
    {
        util::CheckedLockGuard guard(m_route_mutex);
        // Update the location if the base_url is different or a location update is already needed
        m_location_updated = (new_base_url == m_base_url) && m_location_updated;
        update_not_needed = m_location_updated;
    }
    // If the new base_url is the same as the current base_url and the location has already been updated,
    // then we're done
    if (update_not_needed) {
        completion(util::none);
        return;
    }

    // Otherwise, request the location information at the new base URL
    request_location(std::move(completion), new_base_url);
}

std::vector<std::shared_ptr<User>> App::all_users()
{
    util::CheckedLockGuard lock(m_user_mutex);
    auto user_ids = m_metadata_store->get_all_users();
    std::vector<std::shared_ptr<User>> users;
    users.reserve(user_ids.size());
    for (auto& user_id : user_ids) {
        users.push_back(get_user_for_id(user_id));
    }
    return users;
}

void App::get_profile(const std::shared_ptr<User>& user,
                      UniqueFunction<void(const std::shared_ptr<User>&, Optional<AppError>)>&& completion)
{
    Request req;
    req.method = HttpMethod::get;
    req.url = url_for_path("/auth/profile");
    req.timeout_ms = m_request_timeout_ms;
    req.uses_refresh_token = false;

    do_authenticated_request(
        std::move(req), user,
        [completion = std::move(completion), self = shared_from_this(), user,
         this](const Response& profile_response) {
            if (auto error = AppUtils::check_for_errors(profile_response)) {
                return completion(nullptr, std::move(error));
            }

            try {
                auto profile_json = parse<BsonDocument>(profile_response.body);
                auto identities_json = get<BsonArray>(profile_json, "identities");

                std::vector<UserIdentity> identities;
                identities.reserve(identities_json.size());
                for (auto& identity_json : identities_json) {
                    auto doc = as<BsonDocument>(identity_json);
                    identities.push_back({get<std::string>(doc, "id"), get<std::string>(doc, "provider_type")});
                }

                if (auto data = m_metadata_store->get_user(user->user_id())) {
                    data->identities = std::move(identities);
                    data->profile = UserProfile(get<BsonDocument>(profile_json, "data"));
                    m_metadata_store->update_user(user->user_id(), *data);
                    user->update_backing_data(std::move(data));
                }
            }
            catch (const AppError& err) {
                return completion(nullptr, err);
            }

            return completion(user, {});
        });
}

void App::attach_auth_options(BsonDocument& body)
{
    BsonDocument options;

    //    log_debug("App: version info: platform: %1  version: %2 - sdk: %3 - sdk version: %4 - core version: %5",
    //              m_config.device_info.platform, m_config.device_info.platform_version, m_config.device_info.sdk,
    //              m_config.device_info.sdk_version, m_config.device_info.core_version);
    options["appId"] = m_config.app_id;
    options["platform"] = util::get_library_platform();
    options["platformVersion"] = m_config.device_info.platform_version;
    options["sdk"] = m_config.device_info.sdk;
    options["sdkVersion"] = m_config.device_info.sdk_version;
    options["cpuArch"] = util::get_library_cpu_arch();
    options["deviceName"] = m_config.device_info.device_name;
    options["deviceVersion"] = m_config.device_info.device_version;
    options["frameworkName"] = m_config.device_info.framework_name;
    options["frameworkVersion"] = m_config.device_info.framework_version;
    options["coreVersion"] = REALM_VERSION_STRING;
    options["bundleId"] = m_config.device_info.bundle_id;

    body["options"] = BsonDocument({{"device", options}});
}

void App::log_in_with_credentials(const AppCredentials& credentials, const std::shared_ptr<User>& linking_user,
                                  UniqueFunction<void(const std::shared_ptr<User>&, Optional<AppError>)>&& completion)
{
    if (would_log(util::Logger::Level::debug)) {
        auto app_info = util::format("app_id: %1", m_config.app_id);
        log_debug("App: log_in_with_credentials: %1", app_info);
    }
    // if we try logging in with an anonymous user while there
    // is already an anonymous session active, reuse it
    std::shared_ptr<User> anon_user;
    if (credentials.provider() == AuthProvider::ANONYMOUS) {
        util::CheckedLockGuard lock(m_user_mutex);
        for (auto& [_, user] : m_users) {
            if (user->is_anonymous()) {
                anon_user = user->shared_from_this();
                m_current_user = anon_user;
                m_metadata_store->set_current_user(user->user_id());
                break;
            }
        }
    }

    if (anon_user) {
        emit_change_to_subscribers(*this);
        completion(anon_user, util::none);
        return;
    }

    if (linking_user) {
        util::CheckedLockGuard lock(m_user_mutex);
        if (!verify_user_present(linking_user)) {
            return completion(nullptr, AppError(ErrorCodes::ClientUserNotFound, "The specified user was not found."));
        }
    }

    // construct the route
    std::string route = util::format("%1/providers/%2/login%3", auth_route(), credentials.provider_as_string(),
                                     linking_user ? "?link=true" : "");

    BsonDocument body = credentials.serialize_as_bson();
    attach_auth_options(body);

    do_request(
        {HttpMethod::post, route, m_request_timeout_ms,
         get_request_headers(linking_user, RequestTokenType::AccessToken), Bson(body).to_string()},
        [completion = std::move(completion), credentials, linking_user, self = shared_from_this(),
         this](const Response& response) mutable {
            if (auto error = AppUtils::check_for_errors(response)) {
                log_error("App: log_in_with_credentials failed: %1 message: %2", response.http_status_code,
                          error->what());
                return completion(nullptr, std::move(error));
            }

            std::shared_ptr<User> sync_user = linking_user;
            try {
                auto json = parse<BsonDocument>(response.body);
                if (linking_user) {
                    if (auto user_data = m_metadata_store->get_user(linking_user->user_id())) {
                        user_data->access_token = RealmJWT(get<std::string>(json, "access_token"));
                        // maybe a callback for this?
                        m_metadata_store->update_user(linking_user->user_id(), *user_data);
                        linking_user->update_backing_data(std::move(user_data));
                    }
                }
                else {
                    auto user_id = get<std::string>(json, "user_id");
                    m_metadata_store->create_user(user_id, get<std::string>(json, "refresh_token"),
                                                  get<std::string>(json, "access_token"),
                                                  get<std::string>(json, "device_id"));
                    util::CheckedLockGuard lock(m_user_mutex);
                    user_data_updated(user_id); // FIXME: needs to be callback from metadata store
                    sync_user = get_user_for_id(user_id);
                }
            }
            catch (const AppError& e) {
                return completion(nullptr, e);
            }
            // If the user has not been logged in, then there is a problem with the token
            if (!sync_user->is_logged_in()) {
                return completion(nullptr,
                                  AppError(ErrorCodes::BadToken, "Could not log in user: received malformed JWT"));
            }
            switch_user(sync_user);
            get_profile(sync_user, std::move(completion));
        },
        false);
}

void App::log_in_with_credentials(
    const AppCredentials& credentials,
    util::UniqueFunction<void(const std::shared_ptr<User>&, Optional<AppError>)>&& completion)
{
    App::log_in_with_credentials(credentials, nullptr, std::move(completion));
}

void App::log_out(const std::shared_ptr<User>& user, SyncUser::State new_state,
                  UniqueFunction<void(Optional<AppError>)>&& completion)
{
    if (!user || user->state() == new_state || user->state() == SyncUser::State::Removed) {
        if (completion) {
            completion(util::none);
        }
        return;
    }

    Request req;
    req.method = HttpMethod::del;
    req.url = url_for_path("/auth/session");
    req.timeout_ms = m_request_timeout_ms;
    req.uses_refresh_token = true;
    req.headers = get_request_headers(user);

    m_metadata_store->log_out(user->user_id(), new_state);
    user->update_backing_data(m_metadata_store->get_user(user->user_id()));

    do_request(std::move(req),
               [self = shared_from_this(), completion = std::move(completion)](const Response& response) {
                   auto error = AppUtils::check_for_errors(response);
                   if (!error) {
                       self->emit_change_to_subscribers(*self);
                   }
                   if (completion) {
                       completion(error);
                   }
               });
}

void App::log_out(const std::shared_ptr<User>& user, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    auto new_state = user && user->is_anonymous() ? SyncUser::State::Removed : SyncUser::State::LoggedOut;
    log_out(user, new_state, std::move(completion));
}

void App::log_out(UniqueFunction<void(Optional<AppError>)>&& completion)
{
    log_out(current_user(), std::move(completion));
}

bool App::verify_user_present(const std::shared_ptr<User>& user) const
{
    for (auto& [_, u] : m_users) {
        if (u == user.get())
            return true;
    }
    return false;
}

void App::switch_user(const std::shared_ptr<User>& user)
{
    if (!user || user->state() != SyncUser::State::LoggedIn) {
        throw AppError(ErrorCodes::ClientUserNotLoggedIn, "User is no longer valid or is logged out");
    }
    util::CheckedLockGuard lock(m_user_mutex);
    if (!verify_user_present(user)) {
        throw AppError(ErrorCodes::ClientUserNotFound, "User does not exist");
    }

    m_current_user = user;
    m_metadata_store->set_current_user(user->user_id());
    emit_change_to_subscribers(*this);
}

void App::remove_user(const std::shared_ptr<User>& user, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    if (!user || user->state() == SyncUser::State::Removed) {
        return completion(AppError(ErrorCodes::ClientUserNotFound, "User has already been removed"));
    }

    {
        util::CheckedLockGuard lock(m_user_mutex);
        if (!verify_user_present(user)) {
            return completion(AppError(ErrorCodes::ClientUserNotFound, "No user has been found"));
        }
    }

    if (user->is_logged_in()) {
        log_out(
            user, SyncUser::State::Removed,
            [user, completion = std::move(completion), self = shared_from_this()](const Optional<AppError>& error) {
                user->update_backing_data(std::nullopt);
                if (completion) {
                    completion(error);
                }
            });
    }
    else {
        m_metadata_store->log_out(user->user_id(), SyncUser::State::Removed);
        user->update_backing_data(std::nullopt);
        if (completion) {
            completion(std::nullopt);
        }
    }
}

void App::delete_user(const std::shared_ptr<User>& user, UniqueFunction<void(Optional<AppError>)>&& completion)
{
    if (!user) {
        return completion(AppError(ErrorCodes::ClientUserNotFound, "The specified user could not be found."));
    }
    if (user->state() != SyncUser::State::LoggedIn) {
        return completion(AppError(ErrorCodes::ClientUserNotLoggedIn, "User must be logged in to be deleted."));
    }

    {
        util::CheckedLockGuard lock(m_user_mutex);
        if (!verify_user_present(user)) {
            return completion(AppError(ErrorCodes::ClientUserNotFound, "No user has been found."));
        }
    }

    Request req;
    req.method = HttpMethod::del;
    req.timeout_ms = m_request_timeout_ms;
    req.url = url_for_path("/auth/delete");
    do_authenticated_request(
        std::move(req), user,
        [self = shared_from_this(), completion = std::move(completion), user, this](const Response& response) {
            auto error = AppUtils::check_for_errors(response);
            if (!error) {
                auto user_id = user->user_id();
                user->detach_and_tear_down();
                m_metadata_store->delete_user(*m_file_manager, user_id);
                emit_change_to_subscribers(*self);
            }
            completion(std::move(error));
        });
}

void App::link_user(const std::shared_ptr<User>& user, const AppCredentials& credentials,
                    UniqueFunction<void(const std::shared_ptr<User>&, Optional<AppError>)>&& completion)
{
    if (!user) {
        return completion(nullptr,
                          AppError(ErrorCodes::ClientUserNotFound, "The specified user could not be found."));
    }
    if (user->state() != SyncUser::State::LoggedIn) {
        return completion(nullptr,
                          AppError(ErrorCodes::ClientUserNotLoggedIn, "The specified user is not logged in."));
    }
    if (credentials.provider() == AuthProvider::ANONYMOUS) {
        // FIXME: error code
        return completion(nullptr, AppError(ErrorCodes::ClientUserNotLoggedIn,
                                            "Cannot add anonymous credentials to an existing user."));
    }

    log_in_with_credentials(credentials, user, std::move(completion));
}

void App::refresh_custom_data(const std::shared_ptr<User>& user,
                              UniqueFunction<void(Optional<AppError>)>&& completion)
{
    refresh_access_token(user, false, std::move(completion));
}

void App::refresh_custom_data(const std::shared_ptr<User>& user, bool update_location,
                              UniqueFunction<void(Optional<AppError>)>&& completion)
{
    refresh_access_token(user, update_location, std::move(completion));
}

std::string App::url_for_path(const std::string& path = "") const
{
    util::CheckedLockGuard guard(m_route_mutex);
    return util::format("%1%2", m_base_route, path);
}

std::string App::get_app_route(const Optional<std::string>& hostname) const
{
    if (hostname) {
        return util::format("%1%2%3/%4", *hostname, s_base_path, s_app_path, m_config.app_id);
    }
    return m_app_route;
}

void App::request_location(UniqueFunction<void(std::optional<AppError>)>&& completion,
                           std::optional<std::string>&& new_hostname, std::optional<std::string>&& redir_location,
                           int redirect_count)
{
    // Request the new location information at the new base url hostname; or redir response location if a redirect
    // occurred during the initial location request. redirect_count is used to track the number of sequential
    // redirect responses received during the location update and return an error if this count exceeds
    // max_http_redirects. If neither new_hostname nor redir_location is provided, the current value of m_base_url
    // will be used.
    std::string app_route;
    std::string base_url;
    {
        util::CheckedUniqueLock lock(m_route_mutex);
        // Skip if the location info has already been initialized and a new hostname is not provided
        if (!new_hostname && !redir_location && m_location_updated) {
            // Release the lock before calling the completion function
            lock.unlock();
            completion(util::none);
            return; // early return
        }
        base_url = new_hostname ? *new_hostname : m_base_url;
        // If this is for a redirect after querying new_hostname, then use the redirect location
        if (redir_location)
            app_route = get_app_route(redir_location);
        // If this is querying the new_hostname, then use that location
        else if (new_hostname)
            app_route = get_app_route(new_hostname);
        else
            app_route = get_app_route();
        REALM_ASSERT(!app_route.empty());
    }

    Request req;
    req.method = HttpMethod::get;
    req.url = util::format("%1/location", app_route);
    req.timeout_ms = m_request_timeout_ms;

    log_debug("App: request location: %1", req.url);

    m_config.transport->send_request_to_server(
        req, [self = shared_from_this(), completion = std::move(completion), base_url = std::move(base_url),
              redirect_count](const Response& response) mutable {
            // Check to see if a redirect occurred
            if (AppUtils::is_redirect_status_code(response.http_status_code)) {
                // Make sure we don't do too many redirects (max_http_redirects (20) is an arbitrary number)
                if (redirect_count >= s_max_http_redirects) {
                    completion(AppError{ErrorCodes::ClientTooManyRedirects,
                                        util::format("number of redirections exceeded %1", s_max_http_redirects),
                                        {},
                                        response.http_status_code});
                    return; // early return
                }
                // Handle the redirect response when requesting the location - extract the
                // new location header field and resend the request.
                auto redir_location = AppUtils::extract_redir_location(response.headers);
                if (!redir_location) {
                    // Location not found in the response, pass error response up the chain
                    completion(AppError{ErrorCodes::ClientRedirectError,
                                        "Redirect response missing location header",
                                        {},
                                        response.http_status_code});
                    return;
                }
                // try to request the location info at the new location in the redirect response
                // retry_count is passed in to track the number of subsequent redirection attempts
                self->request_location(std::move(completion), std::move(base_url), std::move(redir_location),
                                       redirect_count + 1);
                return;
            }
            // Location request was successful - update the location info
            auto update_response = self->update_location(response, base_url);
            if (update_response) {
                self->log_error("App: request location failed (%1%2): %3", update_response->code_string(),
                                update_response->additional_status_code
                                    ? util::format(" %1", *update_response->additional_status_code)
                                    : "",
                                update_response->reason());
            }
            completion(update_response);
        });
}

std::optional<AppError> App::update_location(const Response& response, const std::string& base_url)
{
    // Validate the location info response for errors and update the stored location info if it is
    // a valid response. base_url is the new hostname or m_base_url value when request_location()
    // was called.

    if (auto error = AppUtils::check_for_errors(response)) {
        return error;
    }

    // Update the location info with the data from the response
    try {
        auto json = parse<BsonDocument>(response.body);
        auto hostname = get<std::string>(json, "hostname");
        auto ws_hostname = get<std::string>(json, "ws_hostname");
        {
            util::CheckedLockGuard guard(m_route_mutex);
            // Update the local hostname and path information
            update_hostname(hostname, ws_hostname, base_url);
            m_location_updated = true;
            // Provide the Device Sync websocket route to the SyncManager
            m_sync_manager->set_sync_route(make_sync_route());
        }
    }
    catch (const AppError& ex) {
        return ex;
    }
    return util::none;
}

void App::update_location_and_resend(Request&& request, UniqueFunction<void(const Response& response)>&& completion,
                                     Optional<std::string>&& redir_location)
{
    // Update the location information if a redirect response was received or m_location_updated == false
    // and then send the request to the server with request.url updated to the new AppServices hostname.
    request_location(
        [completion = std::move(completion), request = std::move(request),
         self = shared_from_this()](Optional<AppError> error) mutable {
            if (error) {
                // Operation failed, pass it up the chain
                return completion(AppUtils::make_apperror_response(*error));
            }

            // If the location info was updated, update the original request to point
            // to the new location URL.
            auto comp = AppUtils::split_url(request.url);
            if (!comp.is_ok()) {
                throw Exception(comp.get_status());
            }
            request.url = self->get_host_url() + comp.get_value().request;

            // Retry the original request with the updated url
            self->m_config.transport->send_request_to_server(request, [self = std::move(self),
                                                                       completion = std::move(completion),
                                                                       request](const Response& response) mutable {
                self->check_for_redirect_response(std::move(request), response, std::move(completion));
            });
        },
        // The base_url is not changing for this request
        util::none, std::move(redir_location));
}

void App::post(std::string&& route, UniqueFunction<void(Optional<AppError>)>&& completion, const BsonDocument& body)
{
    do_request(Request{HttpMethod::post, std::move(route), m_request_timeout_ms, get_request_headers(),
                       Bson(body).to_string()},
               handle_default_response(std::move(completion)));
}

void App::do_request(Request&& request, UniqueFunction<void(const Response& response)>&& completion,
                     bool update_location)
{
    // Make sure the timeout value is set to the configured request timeout value
    request.timeout_ms = m_request_timeout_ms;

    // Verify the request URL to make sure it is valid
    if (auto comp = AppUtils::split_url(request.url); !comp.is_ok()) {
        throw Exception(comp.get_status());
    }

    // Refresh the location info when app is created or when requested (e.g. after a websocket redirect)
    // to ensure the http and websocket URL information is up to date.
    {
        util::CheckedUniqueLock lock(m_route_mutex);
        if (update_location) {
            // If requesting a location update, force the location to be updated before sending the request.
            m_location_updated = false;
        }
        if (!m_location_updated) {
            lock.unlock();
            // Location info needs to be requested, update the location info and then send the request
            update_location_and_resend(std::move(request), std::move(completion));
            return; // early return
        }
    }

    // If location info has already been updated, then send the request directly
    m_config.transport->send_request_to_server(
        request,
        [self = shared_from_this(), completion = std::move(completion), request](const Response& response) mutable {
            self->check_for_redirect_response(std::move(request), response, std::move(completion));
        });
}

void App::check_for_redirect_response(Request&& request, const Response& response,
                                      UniqueFunction<void(const Response& response)>&& completion)
{
    // If this isn't a redirect response, then we're done
    if (!AppUtils::is_redirect_status_code(response.http_status_code)) {
        return completion(response);
    }

    // Handle a redirect response when sending the original request - extract the location
    // header field and resend the request.
    auto redir_location = AppUtils::extract_redir_location(response.headers);
    if (!redir_location) {
        // Location not found in the response, pass error response up the chain
        return completion(AppUtils::make_clienterror_response(
            ErrorCodes::ClientRedirectError, "Redirect response missing location header", response.http_status_code));
    }

    // Request the location info at the new location - once this is complete, the original
    // request will be sent to the new server
    update_location_and_resend(std::move(request), std::move(completion), std::move(redir_location));
}

void App::do_authenticated_request(Request&& request, const std::shared_ptr<User>& sync_user,
                                   util::UniqueFunction<void(const Response&)>&& completion)
{
    request.headers = get_request_headers(sync_user, request.uses_refresh_token ? RequestTokenType::RefreshToken
                                                                                : RequestTokenType::AccessToken);

    log_debug("App: do_authenticated_request: %1 %2", httpmethod_to_string(request.method), request.url);
    auto completion_2 = [completion = std::move(completion), request, sync_user,
                         self = shared_from_this()](const Response& response) mutable {
        if (auto error = AppUtils::check_for_errors(response)) {
            self->handle_auth_failure(std::move(*error), std::move(response), std::move(request), sync_user,
                                      std::move(completion));
        }
        else {
            completion(response);
        }
    };
    do_request(std::move(request), std::move(completion_2));
}

void App::handle_auth_failure(const AppError& error, const Response& response, Request&& request,
                              const std::shared_ptr<User>& sync_user,
                              util::UniqueFunction<void(const Response&)>&& completion)
{
    // Only handle auth failures
    if (*error.additional_status_code == 401) {
        if (request.uses_refresh_token) {
            if (sync_user && sync_user->is_logged_in()) {
                sync_user->log_out();
            }
            completion(response);
            return;
        }
    }
    else {
        completion(response);
        return;
    }

    refresh_access_token(sync_user, false,
                         [self = shared_from_this(), request = std::move(request), completion = std::move(completion),
                          response = std::move(response), sync_user](Optional<AppError>&& error) mutable {
                             if (!error) {
                                 // assign the new access_token to the auth header
                                 request.headers = get_request_headers(sync_user, RequestTokenType::AccessToken);
                                 self->do_request(std::move(request), std::move(completion));
                             }
                             else {
                                 // pass the error back up the chain
                                 completion(std::move(response));
                             }
                         });
}

/// MARK: - refresh access token
void App::refresh_access_token(const std::shared_ptr<User>& sync_user, bool update_location,
                               util::UniqueFunction<void(Optional<AppError>)>&& completion)
{
    if (!sync_user) {
        completion(AppError(ErrorCodes::ClientUserNotFound, "No current user exists"));
        return;
    }

    if (!sync_user->is_logged_in()) {
        completion(AppError(ErrorCodes::ClientUserNotLoggedIn, "The user is not logged in"));
        return;
    }

    log_debug("App: refresh_access_token: email: %1 %2", sync_user->user_profile().email(),
              update_location ? "(updating location)" : "");

    // If update_location is set, force the location info to be updated before sending the request
    do_request(
        {HttpMethod::post, url_for_path("/auth/session"), m_request_timeout_ms,
         get_request_headers(sync_user, RequestTokenType::RefreshToken)},
        [completion = std::move(completion), self = shared_from_this(), sync_user](const Response& response) {
            if (auto error = AppUtils::check_for_errors(response)) {
                return completion(std::move(error));
            }

            try {
                auto json = parse<BsonDocument>(response.body);
                RealmJWT access_token{get<std::string>(json, "access_token")};
                if (auto data = self->m_metadata_store->get_user(sync_user->user_id())) {
                    data->access_token = access_token;
                    self->m_metadata_store->update_user(sync_user->user_id(), *data);
                    sync_user->update_backing_data(std::move(data));
                }
            }
            catch (AppError& err) {
                return completion(std::move(err));
            }

            return completion(util::none);
        },
        update_location);
}

std::string App::function_call_url_path() const
{
    util::CheckedLockGuard guard(m_route_mutex);
    return util::format("%1/functions/call", m_app_route);
}

void App::call_function(const std::shared_ptr<User>& user, const std::string& name, std::string_view args_ejson,
                        const Optional<std::string>& service_name_opt,
                        UniqueFunction<void(const std::string*, Optional<AppError>)>&& completion)
{
    auto service_name = service_name_opt ? *service_name_opt : "<none>";
    if (would_log(util::Logger::Level::debug)) {
        log_debug("App: call_function: %1 service_name: %2 args_bson: %3", name, service_name, args_ejson);
    }

    auto args = util::format("{\"arguments\":%1,\"name\":%2%3}", args_ejson, nlohmann::json(name).dump(),
                             service_name_opt ? (",\"service\":" + nlohmann::json(service_name).dump()) : "");

    do_authenticated_request(
        Request{HttpMethod::post, function_call_url_path(), m_request_timeout_ms, {}, std::move(args), false}, user,
        [self = shared_from_this(), name = name, service_name = std::move(service_name),
         completion = std::move(completion)](const Response& response) {
            if (auto error = AppUtils::check_for_errors(response)) {
                self->log_error("App: call_function: %1 service_name: %2 -> %3 ERROR: %4", name, service_name,
                                response.http_status_code, error->what());
                return completion(nullptr, error);
            }
            completion(&response.body, util::none);
        });
}

void App::call_function(const std::shared_ptr<User>& user, const std::string& name, const BsonArray& args_bson,
                        const Optional<std::string>& service_name,
                        UniqueFunction<void(Optional<Bson>&&, Optional<AppError>)>&& completion)
{
    auto service_name2 = service_name ? *service_name : "<none>";
    std::stringstream args_ejson;
    args_ejson << "[";
    for (auto&& arg : args_bson) {
        if (&arg != &args_bson.front())
            args_ejson << ',';
        args_ejson << arg.toJson();
    }
    args_ejson << "]";

    call_function(user, name, std::move(args_ejson).str(), service_name,
                  [self = shared_from_this(), name, service_name = std::move(service_name2),
                   completion = std::move(completion)](const std::string* response, util::Optional<AppError> err) {
                      if (err) {
                          return completion({}, err);
                      }
                      if (!response) {
                          return completion({}, AppError{ErrorCodes::AppUnknownError, "Empty response from server"});
                      }
                      util::Optional<Bson> body_as_bson;
                      try {
                          body_as_bson = bson::parse(*response);
                          if (self->would_log(util::Logger::Level::debug)) {
                              self->log_debug("App: call_function: %1 service_name: %2 - results: %3", name,
                                              service_name, body_as_bson ? body_as_bson->to_string() : "<none>");
                          }
                      }
                      catch (const std::exception& e) {
                          self->log_error("App: call_function: %1 service_name: %2 - error parsing result: %3", name,
                                          service_name, e.what());
                          return completion(util::none, AppError(ErrorCodes::BadBsonParse, e.what()));
                      };
                      completion(std::move(body_as_bson), util::none);
                  });
}

void App::call_function(const std::shared_ptr<User>& user, const std::string& name, const BsonArray& args_bson,
                        UniqueFunction<void(Optional<bson::Bson>&&, Optional<AppError>)>&& completion)
{
    call_function(user, name, args_bson, util::none, std::move(completion));
}

void App::call_function(const std::string& name, const BsonArray& args_bson,
                        const Optional<std::string>& service_name,
                        UniqueFunction<void(Optional<bson::Bson>&&, Optional<AppError>)>&& completion)
{
    call_function(current_user(), name, args_bson, service_name, std::move(completion));
}

void App::call_function(const std::string& name, const BsonArray& args_bson,
                        UniqueFunction<void(Optional<bson::Bson>&&, Optional<AppError>)>&& completion)
{
    call_function(current_user(), name, args_bson, std::move(completion));
}

Request App::make_streaming_request(const std::shared_ptr<User>& user, const std::string& name,
                                    const BsonArray& args_bson, const Optional<std::string>& service_name) const
{
    auto args = BsonDocument{
        {"arguments", args_bson},
        {"name", name},
    };
    if (service_name) {
        args["service"] = *service_name;
    }
    const auto args_json = Bson(args).to_string();

    auto args_base64 = std::string(util::base64_encoded_size(args_json.size()), '\0');
    util::base64_encode(args_json, args_base64);

    auto url = function_call_url_path() + "?baas_request=" + util::uri_percent_encode(args_base64);
    if (user) {
        url += "&baas_at=";
        url += user->access_token(); // doesn't need url encoding
    }

    return Request{
        HttpMethod::get,
        url,
        m_request_timeout_ms,
        {{"Accept", "text/event-stream"}},
    };
}

PushClient App::push_notification_client(const std::string& service_name)
{
    return PushClient(service_name, m_config.app_id, m_request_timeout_ms,
                      std::shared_ptr<AuthRequestClient>(shared_from_this(), this));
}

// MARK: - UserProvider

void App::register_sync_user(User& user)
{
    auto& tracked_user = m_users[user.user_id()];
    REALM_ASSERT(!tracked_user);
    tracked_user = &user;
    user.update_backing_data(m_metadata_store->get_user(user.user_id()));
}

void App::unregister_sync_user(User& user)
{
    util::CheckedLockGuard lock(m_user_mutex);
    REALM_ASSERT(m_users.count(user.user_id()));
    m_users.erase(user.user_id());
}

bool App::immediately_run_file_actions(std::string_view realm_path)
{
    return m_metadata_store->immediately_run_file_actions(*m_file_manager, realm_path);
}

std::string App::path_for_realm(const SyncConfig& config, std::optional<std::string> custom_file_name) const
{
    return m_file_manager->path_for_realm(config, std::move(custom_file_name));
}

} // namespace app
} // namespace realm

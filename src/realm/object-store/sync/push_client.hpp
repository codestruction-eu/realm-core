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

#ifndef PUSH_CLIENT_HPP
#define PUSH_CLIENT_HPP

#include <realm/util/functional.hpp>

#include <memory>
#include <optional>
#include <string>

namespace realm::app {
class AuthRequestClient;
class User;
struct AppError;

class PushClient {
public:
    PushClient(const std::string& service_name, const std::string& app_id,
               std::shared_ptr<AuthRequestClient>&& auth_request_client)
        : m_service_name(service_name)
        , m_app_id(app_id)
        , m_auth_request_client(std::move(auth_request_client))
    {
    }

    ~PushClient();
    PushClient(const PushClient&) = default;
    PushClient(PushClient&&) = default;
    PushClient& operator=(const PushClient&) = default;
    PushClient& operator=(PushClient&&) = default;


    /// Register a device for push notifications.
    /// @param registration_token GCM registration token for the device.
    /// @param sync_user The sync user requesting push registration.
    /// @param completion An error will be returned should something go wrong.
    void register_device(const std::string& registration_token, const std::shared_ptr<User>& sync_user,
                         util::UniqueFunction<void(std::optional<AppError>)>&& completion);


    /// Deregister a device for push notificatons, no token or device id needs to be passed
    /// as it is linked to the user in MongoDB Realm Cloud.
    /// @param sync_user The sync user requesting push degistration.
    /// @param completion An error will be returned should something go wrong.
    void deregister_device(const std::shared_ptr<User>& sync_user,
                           util::UniqueFunction<void(std::optional<AppError>)>&& completion);

private:
    std::string m_service_name;
    std::string m_app_id;
    std::shared_ptr<AuthRequestClient> m_auth_request_client;
};

} // namespace realm::app

#endif /* PUSH_CLIENT_HPP */

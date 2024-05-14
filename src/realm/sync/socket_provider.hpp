///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2022 Realm Inc.
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
///////////////////////////////////////////////////////////////////////////////

#pragma once

#include <realm/status.hpp>
#include <realm/sync/config.hpp>
#include <realm/sync/network/websocket_error.hpp>
#include <realm/util/functional.hpp>
#include <realm/util/optional.hpp>
#include <realm/util/span.hpp>

#include <map>
#include <memory>
#include <string>

namespace realm::sync {
namespace websocket {
enum class WebSocketError;
}

struct WebSocketEndpoint;
struct WebSocketInterface;
// A struct representing the possible events a WebSocket produced by a SyncSocketProvider
// can observe.
struct WebSocketEvent {
    struct Close {
        bool was_clean;
        websocket::WebSocketError error_code;
        std::string_view message;
    };

    struct Error {};

    struct Message {
        util::Span<const char> bytes;
    };

    struct Open {
        std::string_view protocol;
    };

    bool is_terminal_event() const noexcept
    {
        return mpark::holds_alternative<Close>(event) || mpark::holds_alternative<Error>(event);
    }

    mpark::variant<Close, Error, Message, Open> event;
};

/// Sync Socket Provider interface that provides the event loop and WebSocket
/// factory used by the SyncClient.
///
/// All callback and event operations in the SyncClient must be completed in
/// the order in which they were issued (via post() or timer) to the event
/// loop and cannot be run in parallel. It is up to the custom event loop
/// implementation to determine if these are run on the same thread or a
/// thread pool as long as it is guaranteed that the callback handler
/// functions are processed in order and not run concurrently.
///
/// The implementation of a SyncSocketProvider must support the following
/// operations that post handler functions (via by the Sync client) onto the
/// event loop:
/// * Post a handler function directly onto the event loop
/// * Post a handler function when the specified timer duration expires
///
/// The event loop is not required to be a single thread as long as the
/// following requirements are satisfied:
/// * handler functions are called in the order they were posted to the
/// event loop queue, and
/// * a handler function runs to completion before the next handler function
/// is called.
///
/// The SyncSocketProvider also provides a WebSocket interface for
/// connecting to the server via a WebSocket connection.
class SyncSocketProvider {
public:
    /// Function handler typedef
    using FunctionHandler = util::UniqueFunction<void(Status)>;

    /// The Timer object used to track a timer that was started on the event
    /// loop.
    ///
    /// This object provides a cancel() mechanism to cancel the timer. The
    /// handler function for this timer must be called with a Status of
    /// ErrorCodes::OperationAborted error code if the timer is canceled.
    ///
    /// Custom event loop implementations will need to create a subclass of
    /// Timer that provides access to the underlying implementation to cancel
    /// the timer.
    struct Timer {
        /// Cancels the timer and destroys the timer instance.
        virtual ~Timer() = default;
        /// Cancel the timer immediately. Does nothing if the timer has
        /// already expired or been cancelled.
        virtual void cancel() = 0;
    };

    /// Other class typedefs
    using SyncTimer = std::unique_ptr<SyncSocketProvider::Timer>;

    /// The event loop implementation must ensure the event loop is stopped and
    /// flushed when the object is destroyed. If the event loop is processed by
    /// a thread, the thread must be joined as part of this operation.
    virtual ~SyncSocketProvider() = default;


    virtual std::unique_ptr<WebSocketInterface> connect(util::UniqueFunction<void(WebSocketEvent&&)> observer,
                                                        WebSocketEndpoint&& endpoint) = 0;

    /// Submit a handler function to be executed by the event loop (thread).
    ///
    /// Register the specified handler function to be queued on the event loop
    /// for immediate asynchronous execution. The specified handler will be
    /// executed by an expression on the form `handler()`. If the the handler
    /// object is movable, it will never be copied. Otherwise, it will be
    /// copied as necessary.
    ///
    /// This function is thread-safe and can be called by any thread. It can
    /// also be called from other post() handler function.
    ///
    /// The handler will never be called as part of the execution of post(). If
    /// post() is called on a thread separate from the event loop, the handler
    /// may be called before post() returns.
    ///
    /// Handler functions added through post() must be executed in the order
    /// they are added. More precisely, if post() is called twice to add two
    /// handlers, A and B, and the execution of post(A) ends before the
    /// beginning of the execution of post(B), then A is guaranteed to execute
    /// before B.
    ///
    /// @param handler The handler function to be queued on the event loop.
    virtual void post(FunctionHandler&& handler) = 0;

    /// Create and register a new timer whose handler function will be posted
    /// to the event loop when the provided delay expires.
    ///
    /// This is a one shot timer and the Timer class returned becomes invalid
    /// once the timer has expired. A new timer will need to be created to wait
    /// again.
    ///
    /// @param delay The duration to wait in ms before the timer expires.
    /// @param handler The handler function to be called on the event loop
    ///                when the timer expires.
    ///
    /// @return A pointer to the Timer object that can be used to cancel the
    /// timer. The timer will also be canceled if the Timer object returned is
    /// destroyed.
    virtual SyncTimer create_timer(std::chrono::milliseconds delay, FunctionHandler&& handler) = 0;

    /// Temporary functions added to support the default socket provider until
    /// it is fully integrated. Will be removed in future PRs.
    virtual void stop(bool = false) {}
};

/// Struct that defines the endpoint to create a new websocket connection.
/// Many of these values come from the SyncClientConfig passed to SyncManager when
/// it was created.
struct WebSocketEndpoint {
    using port_type = sync::port_type;

    std::string address;                // Host address
    port_type port;                     // Host port number
    std::string path;                   // Includes access token in query.
    std::vector<std::string> protocols; // Array of one or more websocket protocols
    bool is_ssl;                        // true if SSL should be used

    /// DEPRECATED - These will be removed in a future release
    /// These fields are deprecated and should not be used by custom socket provider implementations
    std::map<std::string, std::string> headers; // Only includes "custom" headers.
    bool verify_servers_ssl_certificate;
    util::Optional<std::string> ssl_trust_certificate_path;
    std::function<SyncConfig::SSLVerifyCallback> ssl_verify_callback;
    util::Optional<SyncConfig::ProxyConfig> proxy;
};


/// The WebSocket base class that is used by the SyncClient to send data over the
/// WebSocket connection with the server. This is the class that is returned by
/// SyncSocketProvider::connect() when a connection to an endpoint is requested.
/// If an error occurs while establishing the connection, the error is presented
/// to the WebSocketObserver provided when the WebSocket was created.
struct WebSocketInterface {
    /// The destructor must close the websocket connection when the WebSocket object
    /// is destroyed
    virtual ~WebSocketInterface() = default;


    /// For implementations that support it, return the app services request ID header
    /// value, i.e. the "X-Appservices-Request-Id" header value.
    ///
    /// TODO: This will go away with RCORE-1380 since it's not strictly available in the
    /// websocket spec. If HTTP headers aren't available, the default implementation of
    /// returning an empty string is okay.
    virtual std::string_view get_appservices_request_id() const noexcept
    {
        return {};
    }

    /// Write data asynchronously to the WebSocket connection. The handler function
    /// will be called when the data has been sent successfully. The WebSocketOberver
    /// provided when the WebSocket was created will be called if any errors occur
    /// during the write operation.
    /// @param data A util::Span containing the data to be sent to the server.
    /// @param handler The handler function to be called when the data has been sent
    ///                successfully or the websocket has been closed (with
    ///                ErrorCodes::OperationAborted). If an error occurs during the
    ///                write operation, the websocket will be closed and the error
    ///                will be provided via the websocket_closed_handler() function.
    virtual void async_write_binary(util::Span<const char> data, SyncSocketProvider::FunctionHandler&& handler) = 0;

    /// Closes the websocket. Must be called from the event loop of the SyncSocketProvider.
    /// No further events will be delivered to the observer and no further messages
    /// can be sent, although messages that had already been sent may complete.
    virtual void close() = 0;
};


} // namespace realm::sync

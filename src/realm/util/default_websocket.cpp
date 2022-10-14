#include <realm/util/default_websocket.hpp>

#include <realm/util/network.hpp>
#include <realm/util/network_ssl.hpp>
#include <realm/util/random.hpp>
#include <realm/util/scope_exit.hpp>
#include <realm/util/websocket.hpp>

namespace realm::util::websocket {

namespace {
class DefaultWebSocketImpl final : public WebSocket, public websocket::Config {
public:
    DefaultWebSocketImpl(const std::string& user_agent_string, const std::shared_ptr<util::Logger>& logger,
                         std::shared_ptr<DefaultEventLoopClient>& event_loop, WebSocketObserver& observer,
                         Endpoint&& endpoint)
        : WebSocket(user_agent_string)
        , m_logger_ptr{logger}
        , m_logger{*m_logger_ptr}
        , m_event_loop(event_loop)
        , m_observer(observer)
        , m_endpoint(std::move(endpoint))
        , m_random{}
        , m_websocket(*this)
    {
        REALM_ASSERT(m_event_loop != nullptr);
        util::seed_prng_nondeterministically(m_random);
        initiate_resolve();
    }

    void async_write_binary(const char* data, size_t size, util::UniqueFunction<void()>&& handler) override
    {
        m_websocket.async_write_binary(data, size, std::move(handler));
    }

    // public for HTTPClient CRTP, but not on the EZSocket interface, so de-facto private
    void async_read(char*, std::size_t, ReadCompletionHandler) override;
    void async_read_until(char*, std::size_t, char, ReadCompletionHandler) override;
    void async_write(const char*, std::size_t, WriteCompletionHandler) override;

private:
    using milliseconds_type = std::int_fast64_t;

    util::network::Service& get_service()
    {
        REALM_ASSERT(m_event_loop != nullptr);
        return m_event_loop->get_service();
    }

    util::Logger& websocket_get_logger() noexcept override
    {
        return m_logger;
    }
    std::mt19937_64& websocket_get_random() noexcept override
    {
        return m_random;
    }

    void websocket_handshake_completion_handler(const util::HTTPHeaders& headers) override
    {
        const std::string empty;
        auto it = headers.find("Sec-WebSocket-Protocol");
        m_observer.websocket_handshake_completion_handler(it == headers.end() ? empty : it->second);
    }
    void websocket_read_error_handler(std::error_code ec) override
    {
        m_logger.error("Reading failed: %1", ec.message()); // Throws
        m_observer.websocket_read_or_write_error_handler(ec);
    }
    void websocket_write_error_handler(std::error_code ec) override
    {
        m_logger.error("Writing failed: %1", ec.message()); // Throws
        m_observer.websocket_read_or_write_error_handler(ec);
    }
    void websocket_handshake_error_handler(std::error_code ec, const util::HTTPHeaders*,
                                           const std::string_view* body) override
    {
        m_observer.websocket_handshake_error_handler(ec, body);
    }
    void websocket_protocol_error_handler(std::error_code ec) override
    {
        m_observer.websocket_protocol_error_handler(ec);
    }
    bool websocket_close_message_received(std::error_code ec, StringData message) override
    {
        return m_observer.websocket_close_message_received(ec, message);
    }
    bool websocket_binary_message_received(const char* ptr, std::size_t size) override
    {
        return m_observer.websocket_binary_message_received(ptr, size);
    }

    void initiate_resolve();
    void handle_resolve(std::error_code, util::network::Endpoint::List);
    void initiate_tcp_connect(util::network::Endpoint::List, std::size_t);
    void handle_tcp_connect(std::error_code, util::network::Endpoint::List, std::size_t);
    void initiate_http_tunnel();
    void handle_http_tunnel(std::error_code);
    void initiate_websocket_or_ssl_handshake();
    void initiate_ssl_handshake();
    void handle_ssl_handshake(std::error_code);
    void initiate_websocket_handshake();
    void handle_connection_established();

    void schedule_urgent_ping();
    void initiate_ping_delay(milliseconds_type now);
    void handle_ping_delay();
    void initiate_pong_timeout();
    void handle_pong_timeout();

    std::shared_ptr<util::Logger> m_logger_ptr;
    util::Logger& m_logger;
    std::shared_ptr<DefaultEventLoopClient> m_event_loop;
    WebSocketObserver& m_observer;
    const Endpoint m_endpoint;
    std::mt19937_64 m_random;
    util::websocket::Socket m_websocket;

    util::Optional<util::network::Resolver> m_resolver;
    util::Optional<util::network::Socket> m_socket;
    util::Optional<util::network::ssl::Context> m_ssl_context;
    util::Optional<util::network::ssl::Stream> m_ssl_stream;
    util::network::ReadAheadBuffer m_read_ahead_buffer;
    util::Optional<util::HTTPClient<DefaultWebSocketImpl>> m_proxy_client;
};


void DefaultWebSocketImpl::async_read(char* buffer, std::size_t size, ReadCompletionHandler handler)
{
    REALM_ASSERT(m_socket);
    if (m_ssl_stream) {
        m_ssl_stream->async_read(buffer, size, m_read_ahead_buffer, std::move(handler)); // Throws
    }
    else {
        m_socket->async_read(buffer, size, m_read_ahead_buffer, std::move(handler)); // Throws
    }
}


void DefaultWebSocketImpl::async_read_until(char* buffer, std::size_t size, char delim, ReadCompletionHandler handler)
{
    REALM_ASSERT(m_socket);
    if (m_ssl_stream) {
        m_ssl_stream->async_read_until(buffer, size, delim, m_read_ahead_buffer, std::move(handler)); // Throws
    }
    else {
        m_socket->async_read_until(buffer, size, delim, m_read_ahead_buffer, std::move(handler)); // Throws
    }
}


void DefaultWebSocketImpl::async_write(const char* data, std::size_t size, WriteCompletionHandler handler)
{
    REALM_ASSERT(m_socket);
    if (m_ssl_stream) {
        m_ssl_stream->async_write(data, size, std::move(handler)); // Throws
    }
    else {
        m_socket->async_write(data, size, std::move(handler)); // Throws
    }
}


void DefaultWebSocketImpl::initiate_resolve()
{
    const std::string& address = m_endpoint.proxy ? m_endpoint.proxy->address : m_endpoint.address;
    const port_type& port = m_endpoint.proxy ? m_endpoint.proxy->port : m_endpoint.port;

    if (m_endpoint.proxy) {
        // logger.detail("Using %1 proxy", proxy->type); // Throws
    }

    m_logger.detail("Resolving '%1:%2'", address, port); // Throws

    util::network::Resolver::Query query(address, util::to_string(port)); // Throws
    auto handler = [this](std::error_code ec, util::network::Endpoint::List endpoints) {
        // If the operation is aborted, the connection object may have been
        // destroyed.
        if (ec != util::error::operation_aborted)
            handle_resolve(ec, std::move(endpoints)); // Throws
    };
    m_resolver.emplace(get_service());                               // Throws
    m_resolver->async_resolve(std::move(query), std::move(handler)); // Throws
}


void DefaultWebSocketImpl::handle_resolve(std::error_code ec, util::network::Endpoint::List endpoints)
{
    if (ec) {
        m_logger.error("Failed to resolve '%1:%2': %3", m_endpoint.address, m_endpoint.port, ec.message()); // Throws
        m_observer.websocket_connect_error_handler(ec);                                                     // Throws
        return;
    }

    initiate_tcp_connect(std::move(endpoints), 0); // Throws
}


void DefaultWebSocketImpl::initiate_tcp_connect(util::network::Endpoint::List endpoints, std::size_t i)
{
    REALM_ASSERT(i < endpoints.size());

    util::network::Endpoint ep = *(endpoints.begin() + i);
    std::size_t n = endpoints.size();
    m_socket.emplace(get_service()); // Throws
    m_socket->async_connect(ep, [this, endpoints = std::move(endpoints), i](std::error_code ec) mutable {
        // If the operation is aborted, the connection object may have been
        // destroyed.
        if (ec != util::error::operation_aborted)
            handle_tcp_connect(ec, std::move(endpoints), i); // Throws
    });
    m_logger.detail("Connecting to endpoint '%1:%2' (%3/%4)", ep.address(), ep.port(), (i + 1), n); // Throws
}


void DefaultWebSocketImpl::handle_tcp_connect(std::error_code ec, util::network::Endpoint::List endpoints,
                                              std::size_t i)
{
    REALM_ASSERT(i < endpoints.size());
    const util::network::Endpoint& ep = *(endpoints.begin() + i);
    if (ec) {
        m_logger.error("Failed to connect to endpoint '%1:%2': %3", ep.address(), ep.port(),
                       ec.message()); // Throws
        std::size_t i_2 = i + 1;
        if (i_2 < endpoints.size()) {
            initiate_tcp_connect(std::move(endpoints), i_2); // Throws
            return;
        }
        // All endpoints failed
        m_logger.error("Failed to connect to '%1:%2': All endpoints failed", m_endpoint.address, m_endpoint.port);
        m_observer.websocket_connect_error_handler(ec); // Throws
        return;
    }

    REALM_ASSERT(m_socket);
    util::network::Endpoint ep_2 = m_socket->local_endpoint();
    m_logger.info("Connected to endpoint '%1:%2' (from '%3:%4')", ep.address(), ep.port(), ep_2.address(),
                  ep_2.port()); // Throws

    // TODO: Handle HTTPS proxies
    if (m_endpoint.proxy) {
        initiate_http_tunnel(); // Throws
        return;
    }

    initiate_websocket_or_ssl_handshake(); // Throws
}

void DefaultWebSocketImpl::initiate_websocket_or_ssl_handshake()
{
    if (m_endpoint.is_ssl) {
        initiate_ssl_handshake(); // Throws
    }
    else {
        initiate_websocket_handshake(); // Throws
    }
}

void DefaultWebSocketImpl::initiate_http_tunnel()
{
    HTTPRequest req;
    req.method = HTTPMethod::Connect;
    req.headers.emplace("Host", util::format("%1:%2", m_endpoint.address, m_endpoint.port));
    // TODO handle proxy authorization

    m_proxy_client.emplace(*this, m_logger);
    auto handler = [this](HTTPResponse response, std::error_code ec) {
        if (ec && ec != util::error::operation_aborted) {
            m_logger.error("Failed to establish HTTP tunnel: %1", ec.message());
            m_observer.websocket_connect_error_handler(ec); // Throws
            return;
        }

        if (response.status != HTTPStatus::Ok) {
            m_logger.error("Proxy server returned response '%1 %2'", response.status, response.reason); // Throws
            std::error_code ec2 =
                util::websocket::Error::bad_response_unexpected_status_code; // FIXME: is this the right error?
            m_observer.websocket_connect_error_handler(ec2);                 // Throws
            return;
        }

        initiate_websocket_or_ssl_handshake(); // Throws
    };

    m_proxy_client->async_request(req, std::move(handler)); // Throws
}

void DefaultWebSocketImpl::initiate_ssl_handshake()
{
    using namespace util::network::ssl;

    if (!m_ssl_context) {
        m_ssl_context.emplace(); // Throws
        if (m_endpoint.verify_servers_ssl_certificate) {
            if (m_endpoint.ssl_trust_certificate_path) {
                m_ssl_context->use_verify_file(*m_endpoint.ssl_trust_certificate_path); // Throws
            }
            else if (!m_endpoint.ssl_verify_callback) {
                m_ssl_context->use_default_verify(); // Throws
            }
        }
    }

    m_ssl_stream.emplace(*m_socket, *m_ssl_context, Stream::client); // Throws
    m_ssl_stream->set_logger(m_logger_ptr.get());
    m_ssl_stream->set_host_name(m_endpoint.address); // Throws
    if (m_endpoint.verify_servers_ssl_certificate) {
        m_ssl_stream->set_verify_mode(VerifyMode::peer); // Throws
        m_ssl_stream->set_server_port(m_endpoint.port);
        if (!m_endpoint.ssl_trust_certificate_path) {
            if (m_endpoint.ssl_verify_callback) {
                m_ssl_stream->use_verify_callback(m_endpoint.ssl_verify_callback);
            }
            else {
                // The included certificates are used if neither the trust
                // certificate nor the callback function is set.
#if REALM_INCLUDE_CERTS
                m_ssl_stream->use_included_certificates(); // Throws
#endif
            }
        }
    }

    auto handler = [this](std::error_code ec) {
        // If the operation is aborted, the connection object may have been
        // destroyed.
        if (ec != util::error::operation_aborted)
            handle_ssl_handshake(ec); // Throws
    };
    m_ssl_stream->async_handshake(std::move(handler)); // Throws

    // FIXME: We also need to perform the SSL shutdown operation somewhere
}


void DefaultWebSocketImpl::handle_ssl_handshake(std::error_code ec)
{
    if (ec) {
        REALM_ASSERT(ec != util::error::operation_aborted);
        m_observer.websocket_ssl_handshake_error_handler(ec); // Throws
        return;
    }

    initiate_websocket_handshake(); // Throws
}


void DefaultWebSocketImpl::initiate_websocket_handshake()
{
    auto headers = util::HTTPHeaders(m_endpoint.headers.begin(), m_endpoint.headers.end());
    headers["User-Agent"] = m_user_agent;

    // Compute the value of the "Host" header.
    const std::uint_fast16_t default_port = (m_endpoint.is_ssl ? 443 : 80);
    auto host = m_endpoint.port == default_port ? m_endpoint.address
                                                : util::format("%1:%2", m_endpoint.address, m_endpoint.port);

    m_websocket.initiate_client_handshake(m_endpoint.path, std::move(host), m_endpoint.protocols,
                                          std::move(headers)); // Throws
}
} // namespace

void DefaultEventLoopClient::stop()
{
    util::CheckedUniqueLock lock(m_mutex);
    // Need to release the lock
    if (auto thread_ptr = std::move(m_thread); thread_ptr != nullptr) {
        m_service.stop();
        m_logger.trace("DefaultEventLoopClient: Event loop thread stopped");
        if (thread_ptr->joinable()) {
            lock.unlock(); // Thread grabs the mutex before updating the state to stopped
            thread_ptr->join();
        }
    }
}

void DefaultEventLoopClient::thread_update_state(State new_state)
{
    util::CheckedLockGuard lock(m_mutex);
    m_state = new_state;
}

// If the service thread is not running, make sure it has been started
bool DefaultEventLoopClient::ensure_service_is_running()
{
    util::CheckedLockGuard lock(m_mutex);
    if (m_state == State::NotStarted) {
        if (m_thread == nullptr) {
            m_logger.trace("DefaultEventLoopClient: Starting event loop thread");
            m_thread = std::make_unique<std::thread>([this]() {
                /*if (g_binding_callback_thread_observer) {
                    g_binding_callback_thread_observer->did_create_thread();
                    auto will_destroy_thread = util::make_scope_exit([&]() noexcept {
                        g_binding_callback_thread_observer->will_destroy_thread();
                    });
                    try {
                        thread_update_state(State::Running);
                        m_service.run(); // Throws
                        thread_update_state(State::Stopped);
                    }
                    catch (std::exception const& e) {
                        thread_update_state(State::Stopped);
                        g_binding_callback_thread_observer->handle_error(e);
                    }
                }
                else {*/
                thread_update_state(State::Running);
                m_service.run(); // Throws
                thread_update_state(State::Stopped);
                //}
            });
        }
        // Return true to indicate the thread is in the process of being started
        // The state will be updated once the thread is up and running
        return true;
    }
    // Return true if the event loop is running
    return m_state == State::Running;
}

std::unique_ptr<WebSocket> DefaultWebSocketFactory::connect(WebSocketObserver* observer, Endpoint&& endpoint)
{
    return std::make_unique<DefaultWebSocketImpl>(m_user_agent, m_logger_ptr, m_event_loop, *observer,
                                                  std::move(endpoint));
}

} // namespace realm::util::websocket

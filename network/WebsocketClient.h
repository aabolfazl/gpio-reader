#ifndef _WEBSOCKET_CLIENT_H_
#define _WEBSOCKET_CLIENT_H_

#include <websocketpp/client.hpp>

#include <mutex>
#include <condition_variable>

#ifndef TLS

#include <websocketpp/config/asio_no_tls_client.hpp>

typedef websocketpp::client <websocketpp::config::asio_client> Client;
#else
#include <websocketpp/config/asio_client.hpp>
typedef websocketpp::socketClient<websocketpp::config::asio_tls_client> Client;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> ContextPtr;
#endif

#include "ProtoSchema.h"

class RequestManager;

class WebSocketClient {
public:
    WebSocketClient(RequestManager *requestManager);

    ~WebSocketClient();

    void onOpen(websocketpp::connection_hdl hdl);

    void onNewMessage(websocketpp::connection_hdl hdl, const Client::message_ptr &);

    void onClose(const websocketpp::connection_hdl &);

#ifdef TLS
    bool verify_subject_alternative_name(const char* hostname, X509* cert);
    bool verify_common_name(char const* hostname, X509* cert);
    bool verify_certificate(const char* hostname, bool preverified, boost::asio::ssl::verify_context& ctx);
    ContextPtr on_tls_init(const char* hostname, const char* ca_file, websocketpp::connection_hdl);
#endif

    void connect(const std::string &hostname, const std::string &port, std::string ca_file);

    void disconnect();

    void sendBinary(char *binary);

private:
    Client socketConnection;
    websocketpp::connection_hdl connection;
    bool inHandshaking = false;

//    std::atomic <bool> socketIsConnect;
//    std::atomic <bool> isRuning;
//    std::mutex m_mutex;
//    std::condition_variable conditionVariable;

    std::thread sendMessageThread;
    RequestManager *requestManager;
    bool isSecure = false;

};


#endif
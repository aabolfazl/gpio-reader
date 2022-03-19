#include "WebsocketClient.h"
#include <openssl/asn1.h>
#include "RequestManager.h"

WebSocketClient::WebSocketClient(RequestManager *requestManager) : connection(websocketpp::connection_hdl()) {
    this->requestManager = requestManager;

    socketConnection.set_access_channels(websocketpp::log::alevel::none);
    socketConnection.clear_access_channels(websocketpp::log::alevel::none);
    socketConnection.init_asio();
    socketConnection.set_open_handler(std::bind(&WebSocketClient::onOpen, this, std::placeholders::_1));
    socketConnection.set_message_handler(std::bind(&WebSocketClient::onNewMessage, this, std::placeholders::_1, std::placeholders::_2));
    socketConnection.set_close_handler(std::bind(&WebSocketClient::onClose, this, std::placeholders::_1));

    socketConnection.set_reuse_addr(true);

//    socketIsConnect = false;
//    isRuning = true;
}

WebSocketClient::~WebSocketClient() {

//    isRuning = false;
//    socketIsConnect = false;
//    conditionVariable.notify_all();

    socketConnection.stop();
//    if (sendMessageThread.joinable()) {
//        sendMessageThread.detach();
//    }
}

void WebSocketClient::onOpen(websocketpp::connection_hdl hdl) {
    std::cout << "Websocket on open" << std::endl;
//    socketIsConnect = true;
    connection = hdl;

    requestManager->onConnectionOpen();
//    std::unique_lock <std::mutex> lck(m_mutex);
//    conditionVariable.notify_one();
}

void WebSocketClient::onNewMessage(websocketpp::connection_hdl hdl, const Client::message_ptr &msg) {
    if (msg->get_opcode() == websocketpp::frame::opcode::binary) {
        unsigned char buffer[msg.get()->get_payload().size()];
        if (std::copy(msg.get()->get_payload().begin(), msg.get()->get_payload().end(), buffer)) {
            requestManager->onConnectionBinaryReceived(buffer, msg.get()->get_payload().size());
        } else {
            std::cerr << "can not copy and alloc memory from os!" << std::endl;
        }
    } else {
        std::cerr << "received unknown message!" << std::endl;
    }
}

void WebSocketClient::onClose(const websocketpp::connection_hdl &handle) {
    std::cout << "onClose, hdl: " << handle.lock().get() << std::endl;
//    socketIsConnect = false;
}

#ifdef TLS
bool WebSocketClient::verify_subject_alternative_name(const char* hostname, X509* cert) {
    STACK_OF(GENERAL_NAME)* san_names = NULL;

    san_names = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL) {
        return false;
    }

    int san_names_count = sk_GENERAL_NAME_num(san_names);

    bool result = false;

    for (int i = 0; i < san_names_count; i++) {
        const GENERAL_NAME* current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type != GEN_DNS) {
            continue;
        }

#ifdef WIN32
        char const* dns_name = (char const*)ASN1_STRING_get0_data(current_name->d.dNSName);
#else
        char const* dns_name = (char const*)ASN1_STRING_data(current_name->d.dNSName);
#endif
        // Make sure there isn't an embedded NUL character in the DNS name
        if (ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
            break;
        }
        // Compare expected hostname with the CN
        std::cout << "hostname: " << hostname << ", dns_name: " << dns_name << std::endl;
#ifdef WIN32
        result = (stricmp(hostname, dns_name) == 0);
#else
        result = (strcasecmp(hostname, dns_name) == 0);
#endif
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return result;
}

/// Verify that the certificate common name matches the given hostname
bool WebSocketClient::verify_common_name(char const* hostname, X509* cert) {
    // Find the position of the CN field in the Subject field of the certificate
    int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
    if (common_name_loc < 0) {
        return false;
    }

    // Extract the CN field
    X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
    if (common_name_entry == NULL) {
        return false;
    }

    // Convert the CN field to a C string
    ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL) {
        return false;
    }

#ifdef WIN32
    char const* common_name_str = (char const*)ASN1_STRING_get0_data(common_name_asn1);
#else
    char const* common_name_str = (char const*)ASN1_STRING_data(common_name_asn1);
#endif

    // Make sure there isn't an embedded NUL character in the CN
    if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
        return false;
    }

    // Compare expected hostname with the CN
    std::cout << "hostname: " << hostname << ", common_name_str: " << common_name_str << std::endl;
#ifdef WIN32
    return(stricmp(hostname, common_name_str) == 0);
#else
    return (strcasecmp(hostname, common_name_str) == 0);
#endif
}


bool WebSocketClient::verify_certificate(const char* hostname, bool preverified, boost::asio::ssl::verify_context& ctx) {
    int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
    if (depth == 0 && preverified) {
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

        char subject_name[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        std::cout << "Verifying " << subject_name << "\n";

        if (verify_subject_alternative_name(hostname, cert)) {
            return true;
        }
        else if (verify_common_name(hostname, cert)) {
            return true;
        }
        else {
            return false;
        }
    }

    return preverified;
}

ContextPtr WebSocketClient::on_tls_init(const char* hostname, const char* ca_file, websocketpp::connection_hdl) {
    namespace asio = websocketpp::lib::asio;
    ContextPtr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);

    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::single_dh_use);

        ctx->set_verify_mode(boost::asio::ssl::verify_peer);
        //ctx->set_verify_mode(boost::asio::ssl::verify_none);

        ctx->set_verify_callback(bind(&WebSocketClient::verify_certificate, this, hostname, std::placeholders::_1, std::placeholders::_2));

        // Here we load the CA certificates of all CA's that this socketClient trusts.
        ctx->load_verify_file(ca_file);
    }
    catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    return ctx;
}
#endif


void WebSocketClient::connect(const std::string &hostname, const std::string &port, std::string ca_file) {
    std::string uri;
#ifdef TLS
    uri = "wss://" + hostname + ":" + port;
    //uri = "wss://192.168.10.37:9002";
    if (ca_file.empty())
        ca_file = "ca.pem";
    socketClient.set_tls_init_handler(std::bind(&WebSocketClient::on_tls_init, this, hostname.c_str(), ca_file.c_str(), std::placeholders::_1));
#else
    uri = "ws://" + hostname + ":" + port;
#endif

    websocketpp::lib::error_code ec;
    Client::connection_ptr con = socketConnection.get_connection(uri, ec);
    if (ec) {
        socketConnection.get_alog().write(websocketpp::log::alevel::app, ec.message());
        return;
    }

    socketConnection.connect(con);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
//    sendMessageThread = std::thread(std::bind(&WebSocketClient::startTlsHandShake, this));

    socketConnection.run();
}

void WebSocketClient::disconnect() {
//    isRuning = false;
//    socketIsConnect = false;
//    conditionVariable.notify_all();

    socketConnection.stop();
//    sendMessageThread.detach();
    /*
    if (sendMessageThread.joinable())
        sendMessageThread.join();
    */
}

void WebSocketClient::sendBinary(char *binary) {
    socketConnection.send(connection, binary, websocketpp::frame::opcode::binary);
}

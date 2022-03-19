#include "WebsocketClient.h"
#include "semaphore.h"
#include <sys/stat.h>

#ifndef WIN32

#include <signal.h>
#include "proto/MessageContainer.pb.h"

#endif

int main(int argc, char *argv[]) {
//    GOOGLE_PROTOBUF_VERIFY_VERSION;

    std::string hostname = "136.243.189.6", port = "3000", ca_file = "ca.pem";

//    auto header = new proto::MessageContainer::Header();
//    header->set_actionid(proto::ActionMap::CLIENT_HELLO);
//    header->set_id("Test");

//    auto message = new proto::MessageContainer();
//    message->set_message("dsds");
//    message->set_allocated_header(header);

    if (argc == 4) {
        hostname = argv[1];
        port = argv[2];
        ca_file = argv[3];
    }/* else {
        std::cout << "Usage: " << argv[0] << " [hostname] [port] [ca_file]" << std::endl;
        return -1;
    }*/

    WebSocketClient client;
    std::thread t = std::thread([&]() {
        try {
            client.start(hostname, port, ca_file);
        } catch (websocketpp::exception const &e) {
            std::cout << e.what() << std::endl;
        } catch (const std::exception &e) {
            std::cout << e.what() << std::endl;
        } catch (...) {
            std::cout << "unknown error" << std::endl;
        }
    });

#ifndef WIN32
    static Semaphore sem;
    signal(SIGINT, [](int) { sem.post(); });
    sem.wait();
    client.disconnect();
#endif

    if (t.joinable())
        t.join();
#ifdef WIN32
    system("pause");
#endif

    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}
/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#include "RequestManager.h"

#include "ProtoSchema.h"
#include "../Define.h"

RequestManager &RequestManager::getInstance() {
    static RequestManager instance;
    return instance;
}

RequestManager::RequestManager() {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    string hostname = "127.0.0.1", port = "3000", ca_file = "ca.pem";
    cout << "RequestManager" << std::endl;

    socketClient = new WebSocketClient(this);
    clientKey = randomString();
    preSecret = randomString();

    cout << "RequestManager 2" << std::endl;

    thread socketThread = thread([&]() {
        try {
            socketClient->connect(hostname, port, ca_file);
        } catch (websocketpp::exception const &e) {
            std::cout << e.what() << std::endl;
        } catch (const std::exception &e) {
            std::cout << e.what() << std::endl;
        } catch (...) {
            std::cout << "unknown error" << std::endl;
        }
    });

    if (socketThread.joinable()) {
        socketThread.join();
    }
}

RequestManager::~RequestManager() {
    google::protobuf::ShutdownProtobufLibrary();

    if (socketClient != nullptr) {
        socketClient = nullptr;
        delete socketClient;
    }
}

void RequestManager::onConnectionOpen() {
    auto *streamWriter = new ByteArray();

    auto *hello = new ClientSayHello();
    hello->version = version;
    hello->sessionId = sessionId;
    hello->randomKey = clientKey;
    hello->serializeToArray(streamWriter);

    auto header = new MessageContainer::Header();
    header->set_actionid(ActionMap::CLIENT_HELLO);
    header->set_id("startTlsHandShake");

    auto message = new MessageContainer();
    message->set_message(streamWriter->buffer);
    message->set_allocated_header(header);

    int size = message->ByteSize();
    char *array = new char[size];
    message->SerializeToArray(array, size);

    auto message2 = new MessageContainer();
    message2->ParsePartialFromArray(array, size);
    socketClient->sendBinary(array);
    delete streamWriter;
}

void RequestManager::startTlsHandShake() {

//    while (true) {
//        std::unique_lock <std::mutex> lck(m_mutex);
//        conditionVariable.wait(lck, [&]() {
//            return !isRuning || socketIsConnect;
//        });
//        lck.unlock();
//        if (!isRuning)
//            break;

//        std::string user_input;
//        std::cout << "Please enter the message you want to send: " << std::endl;
//        std::getline(std::cin, user_input);
//    }

}

void RequestManager::onConnectionBinaryReceived(unsigned char *binary, int size) {
    auto *messageContainer = new MessageContainer();
    if (messageContainer->ParseFromArray(binary, size)) {
        log_i("parse successfully action id -> %d with uid -> %s", messageContainer->header().actionid(), messageContainer->header().id().c_str());
        readMessageContainer(messageContainer);
    } else {
        log_e("can not parse message from array");
    }
}

void RequestManager::readMessageContainer(MessageContainer *pMessage) {
    try {
        uint8_t constructor = pMessage->header().actionid();
        int size = pMessage->message().size();
        char *array = new char[size];

        if (copy(pMessage->message().begin(), pMessage->message().end(), array)) {
            log_i("%d action id received %p", constructor, pMessage);
            if (handShakeDone) {
// private codes
            } else {
                if (constructor == ActionMap::SERVER_HELLO) {
                    if (inSecuring) {
                        return;
                    }
                    inSecuring = true;

                    auto *serverHello = ServerSayHello::deserializeObject(constructor, array, size);
                    if (serverHello != nullptr) {
                        if (sslVerifyCertificate(serverHello->certificate) == 1) {
                            log_i("Verify Success");
                            serverKey = serverHello->serverRandom;
                            auto *streamWriter = new ByteArray();

                            auto *hello = new ClientSecurityAct();
                            hello->premaster = encrypted_text;
                            hello->serializeToArray(streamWriter);

                            auto header = new MessageContainer::Header();
                            header->set_actionid(ActionMap::CLIENT_SECURITY);
                            header->set_id("CLIENT_SECURITY");

                            auto message = new MessageContainer();
                            message->set_message(streamWriter->buffer);
                            message->set_allocated_header(header);

                            int size = message->ByteSize();
                            char *array = new char[size];
                            message->SerializeToArray(array, size);

                            auto message2 = new MessageContainer();
                            message2->ParsePartialFromArray(array, size);
                            socketClient->sendBinary(array);
                            delete streamWriter;

                            log_i("\nclientKey: %s\nserverKey: %s \npreSecret: %s", clientKey.c_str(), serverKey.c_str(), preSecret.c_str());
                        }
                    }
                } else if (constructor == ActionMap::ERROR_RESPONSE) {
                    inSecuring = false;
                    auto errorObject = new Error();
                    errorObject->readParams(array, size);
                    log_e("error name -> %s message -> %s", errorObject->name.c_str(), errorObject->message.c_str());
                } else if (constructor == ActionMap::CLIENT_SECURITY_RESPONSE) {
                    log_i("CLIENT_SECURITY_RESPONSE successfully!");
                    handShakeDone = true;
                    selectAndSendRequest();
                }
            }
        } else {
            log_e("readMessageContainer could not copy!");
        }
    } catch (...) {
        log_e("Exception handler");
    }
}

void RequestManager::selectAndSendRequest() {

}

int RequestManager::sslVerifyCertificate(const char *server_pem) {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    const char intermediate[] =
            "-----BEGIN CERTIFICATE-----\n"
            "YOUR KEY"
            "-----END CERTIFICATE-----" "\n";

    BIO *clientCert = BIO_new(BIO_s_mem());
    BIO_puts(clientCert, intermediate);
    X509 *issuer = PEM_read_bio_X509(clientCert, NULL, NULL, NULL);
    EVP_PKEY *signing_key = X509_get_pubkey(issuer);

    BIO *certificate = BIO_new(BIO_s_mem());
    BIO_puts(certificate, server_pem);
    X509 *x509 = PEM_read_bio_X509(certificate, NULL, NULL, NULL);

    EVP_PKEY *publicKey = X509_get_pubkey(x509);

    int result = X509_verify(x509, signing_key);

    RSA *rsa = EVP_PKEY_get0_RSA(publicKey);

    if (DEBUG) {
        FILE *ff = fopen("/home/abolfazl/public_key.pem", "w");
        if (PEM_write_RSAPublicKey(ff, rsa) == 0) {
            log_e("Error PEM_write_RSAPublicKey %s", strerror(errno));
        }
        fclose(ff);
    }

    int encrypted_length = RSA_size(rsa);
    strcpy(message, preSecret.c_str());

    encrypted_text = (char *) malloc(encrypted_length);
    if (encrypted_text == NULL) {
        log_e("encrypted_text error");
    }

    int messageLen = strlen(message);
    int res = RSA_public_encrypt(messageLen, (unsigned char *) message, (unsigned char *) encrypted_text, rsa, RSA_PKCS1_OAEP_PADDING);

    log_e("%d %d %d %d", strlen(message), strlen(encrypted_text), res, encrypted_length);

    EVP_PKEY_free(signing_key);
    BIO_free(clientCert);
    BIO_free(certificate);
    X509_free(x509);
    X509_free(issuer);

    return result;
}

string RequestManager::randomString(int len) {
    string result;
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    srand((unsigned) time(NULL) * getpid());

    result.reserve(len);

    for (int i = 0; i < len; ++i) {
        result += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return result;
}


void RequestManager::onConnectionHandshakeDone() {

}

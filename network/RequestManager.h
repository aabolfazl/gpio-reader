/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/
#ifndef _REQUEST_MANAGER_H_
#define _REQUEST_MANAGER_H_

#include "WebsocketClient.h"
#include "proto/MessageContainer.pb.h"
#include "proto/Security.pb.h"
#include "proto/Error.pb.h"
#include "logger/Logger.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace proto;
using namespace std;

class RequestManager {

public:
    static RequestManager &getInstance();

    RequestManager();
    ~RequestManager();

    void onConnectionOpen();

    void onConnectionBinaryReceived(unsigned char binary[], int size);
private:
    WebSocketClient *socketClient;

    char message[33];
    char *encrypted_text = NULL;

    bool handShakeDone = false;
    bool inSecuring = false;
    string version = "1";
    string sessionId = "bi_version";

    string clientKey{};
    string serverKey{};
    string preSecret{};

    void startTlsHandShake();
    void onConnectionHandshakeDone();
    void readMessageContainer(MessageContainer *pMessage);
    int sslVerifyCertificate(const char *server_pem);
    void selectAndSendRequest();
    string randomString(int len = 32);
};

#endif
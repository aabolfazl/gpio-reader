/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#ifndef MASTERMODULE_PROTOSCHEMA_H
#define MASTERMODULE_PROTOSCHEMA_H

#include <string>
#include "AbstractObject.h"

#include "proto/MessageContainer.pb.h"
#include "proto/Security.pb.h"
#include "proto/Error.pb.h"
#include <logger/Logger.h>

class ByteArray;

using namespace std;
using namespace proto;

class Error : AbstractObject {
public:
    static const int constructor = ActionMap::ERROR_RESPONSE;

    string message;
    string name;

    AbstractObject *deserializeResponse(uint32_t constructor, char *binary, int size) override;
    void readParams(char *binary, int size) override;
};

class ClientSayHello : AbstractObject {
public:
    static const int constructor = ActionMap::CLIENT_HELLO;

    string randomKey;
    string sessionId;
    string version;

    bool serializeToArray(ByteArray *writer) override;
    AbstractObject *deserializeResponse(uint32_t constructor, char *binary, int size) override;
};

class ServerSayHello : public AbstractObject {
public:
    static const int constructor = ActionMap::SERVER_HELLO;

    string version;
    string serverRandom;
    string sessionId;
    const char *certificate;

    static ServerSayHello *deserializeObject(uint32_t constructor, char *binary, int size);
    void readParams(char *binary, int size) override;

};

class ClientSecurityAct : AbstractObject {
public:
    static const int constructor = ActionMap::CLIENT_SECURITY;
    char *premaster;

    bool serializeToArray(ByteArray *writer) override;
    AbstractObject *deserializeResponse(uint32_t constructor, char *binary, int size) override;
};

#endif

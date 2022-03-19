/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#include "ProtoSchema.h"
#include "logger/Logger.h"

void Error::readParams(char *binary, int size) {
    auto *error = new ErrorResponse();
    try {
        if (error->ParsePartialFromArray(binary, size)) {
            name = error->name();
            message = error->message();
        }
    } catch (...) {
        log_e("exception on parse proto constructor -> %d", constructor);
    }
}

AbstractObject *Error::deserializeResponse(uint32_t constructor, char *binary, int size) {
    return AbstractObject::deserializeResponse(constructor, binary, size);
}

bool ClientSayHello::serializeToArray(ByteArray *writer) {
    auto sayHello = new ClientHello();
    sayHello->set_allocated_clientrandom(&randomKey);
    sayHello->set_sessionid(sessionId);
    sayHello->set_version(version);

    writer->size = sayHello->ByteSize();
    writer->buffer = new char[writer->size];
    return sayHello->SerializeToArray(writer->buffer, writer->size);
}

AbstractObject *ClientSayHello::deserializeResponse(uint32_t magic, char *binary, int size) {
    return ServerSayHello::deserializeObject(magic, binary, size);
}

ServerSayHello *ServerSayHello::deserializeObject(uint32_t magic, char *binary, int size) {
    if (ServerSayHello::constructor != magic) {
        log_e("can't parse magic %x in ServerSayHello", magic);
        return nullptr;
    }

    auto serverSayHello = new ServerSayHello();
    serverSayHello->readParams(binary, size);
    return serverSayHello;
}

void ServerSayHello::readParams(char *binary, int size) {
    auto *response = new ServerHello();
    response->ParsePartialFromArray(binary, size);

    certificate = response->certificate().c_str();
    serverRandom = response->serverrandom();
    version = response->version();
    sessionId = response->sessionid();
}

bool ClientSecurityAct::serializeToArray(ByteArray *writer) {
    auto sayHello = new ClientSecurity();
    sayHello->set_pre_master_secret(premaster);

    writer->size = sayHello->ByteSize();
    writer->buffer = new char[writer->size];
    return sayHello->SerializeToArray(writer->buffer, writer->size);
}

AbstractObject *ClientSecurityAct::deserializeResponse(uint32_t constructor, char *binary, int size) {
    return AbstractObject::deserializeResponse(constructor, binary, size);
}

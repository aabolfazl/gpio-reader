/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#include "AbstractObject.h"

void AbstractObject::readParams(char *binary, int size) {

}

AbstractObject *AbstractObject::deserializeResponse(uint32_t constructor, char *binary, int size) {
    return nullptr;
}

bool AbstractObject::serializeToArray(ByteArray *writer) {
    return false;
}
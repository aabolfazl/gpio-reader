/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#include "ByteArray.h"

ByteArray::ByteArray() {
    buffer = nullptr;
    size = 0;
}

ByteArray::~ByteArray() {
    if (buffer != nullptr) {
        delete buffer;
        buffer = nullptr;
    }
}

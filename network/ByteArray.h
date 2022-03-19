/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#ifndef MASTERMODULE_BYTEARRAY_H
#define MASTERMODULE_BYTEARRAY_H

#include <cstdint>

class ByteArray {
public:
    ByteArray();
    ~ByteArray();
    char *buffer;
    int size;
};

#endif

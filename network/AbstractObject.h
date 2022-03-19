/*
 * Copyright (C) 2021 Abolfazl Abbasi
 * The is the source code of embedded system modules
 * All rights reserved.
*/

#ifndef MASTERMODULE_ABSTRACTOBJECT_H
#define MASTERMODULE_ABSTRACTOBJECT_H


#include <cstdint>
#include "ByteArray.h"

class AbstractObject {
public:
    virtual void readParams(char *binary, int size);
    virtual AbstractObject *deserializeResponse(uint32_t constructor, char *binary, int size);
    virtual bool serializeToArray(ByteArray *writer);
};

#endif

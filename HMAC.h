//
// Created by Liming Shao on 2018/4/11.
//

#ifndef LIBTOM_DEMO_HMAC_H
#define LIBTOM_DEMO_HMAC_H

#include <stdint.h>

enum HMAC_HASH_TYPE{
    HMAC_MD5,
    HMAC_SHA1,
    HMAC_SHA256,
    HMAC_SHA512
};

int HMAC_HASH(HMAC_HASH_TYPE type, const uint8_t *key, uint32_t keyLen, const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen);



#endif //LIBTOM_DEMO_HMAC_H

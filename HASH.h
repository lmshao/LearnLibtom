//
// Created by Liming Shao on 2018/4/11.
//

#ifndef LIBTOM_DEMO_HASH_H
#define LIBTOM_DEMO_HASH_H

#include <stdint.h>

int MD5(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen);

int SHA1(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen);

int SHA256(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen);

int SHA512(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen);

#endif //LIBTOM_DEMO_HASH_H

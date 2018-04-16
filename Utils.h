//
// Created by Liming Shao on 2018/4/11.
//

#ifndef LIBTOM_DEMO_UTILS_H
#define LIBTOM_DEMO_UTILS_H


#include <stdint.h>

int Byte2Hex(const uint8_t *in, int len, char **out);

int Hex2Byte(const char *in, uint8_t **out, uint32_t *len);

int Base64Encrypt(const uint8_t *plain, uint32_t plainLen, char **base64);

int Base64Decrypt(const char *base64, uint8_t **plain, uint32_t *plainLen);

#endif //LIBTOM_DEMO_UTILS_H

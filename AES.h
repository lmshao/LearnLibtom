//
// Created by Liming Shao on 2018/4/11.
//

#ifndef LIBTOM_DEMO_AES_H
#define LIBTOM_DEMO_AES_H

#include <stdint.h>

enum PaddingType{
    ZEROPADDING,
    PKCS7
};

enum BlockSize{
    BS128 = 16,  // 16 Bytes
    BS192 = 24,  // 24 Bytes
    BS256 = 32  // 32 Bytes
};

enum CryptoOperation{
    ENCRYPTION,
    DECRYPTION
};

int AES_ECB(const uint8_t *key, uint32_t keyLen, const uint8_t *inData, uint32_t inLen, uint8_t **outData, uint32_t *outLen, CryptoOperation crypto);

int AES_Padding(PaddingType type, const uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen);

int AES_UnPadding(PaddingType type, const uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen);

int AES_Test();

#endif //LIBTOM_DEMO_AES_H

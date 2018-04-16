//
// Created by Liming Shao on 2018/4/11.
//

#include <stdio.h>
#include <tomcrypt.h>
#include "HASH.h"

int MD5(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen) {
    hash_state md;
    int dstLen = 16;
    uint8_t *dst = (uint8_t *)malloc(dstLen);
    if (dst == NULL){
        printf("malloc err.\n");
        return 1;
    }

    if (data == NULL || digest == NULL || digestLen == NULL){
        printf("HMAC_HASH param err.\n");
        return 1;
    }

    md5_init(&md);
    md5_process(&md, data, dataLen);
    md5_done(&md, dst);

    *digest = dst;
    *digestLen = (uint32_t)dstLen;
    return 0;
}

int SHA1(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen) {
    hash_state md;
    int dstLen = 20;
    uint8_t *dst = (uint8_t *)malloc(dstLen);
    if (dst == NULL){
        printf("malloc err.\n");
        return 1;
    }

    if (data == NULL || digest == NULL || digestLen == NULL){
        printf("HMAC_HASH param err.\n");
        return 1;
    }

    sha1_init(&md);
    sha1_process(&md, data, dataLen);
    sha1_done(&md, dst);

    *digest = dst;
    *digestLen = (uint32_t)dstLen;
    return 0;
}

int SHA256(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen) {
    hash_state md;
    int dstLen = 32;
    uint8_t *dst = (uint8_t *)malloc(dstLen);
    if (dst == NULL){
        printf("malloc err.\n");
        return 1;
    }

    sha256_init(&md);
    sha256_process(&md, data, dataLen);
    sha256_done(&md, dst);

    *digest = dst;
    *digestLen = (uint32_t)dstLen;

    return 0;
}

int SHA512(const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen) {
    hash_state md;
    int dstLen = 64;
    uint8_t *dst = (uint8_t*)malloc(dstLen);
    if (dst == NULL){
        printf("malloc err.\n");
        return 1;
    }

    if (data == NULL || digest == NULL || digestLen == NULL){
        printf("HMAC_HASH param err.\n");
        return 1;
    }

    sha512_init(&md);
    sha512_process(&md, data, dataLen);
    sha512_done(&md, dst);

    *digest = dst;
    *digestLen = (uint32_t)dstLen;

    return 0;
}

//
// Created by Liming Shao on 2018/4/11.
//

#include "HMAC.h"
#include <tomcrypt.h>

int HMAC_HASH(HMAC_HASH_TYPE type, const uint8_t *key, uint32_t keyLen,
              const uint8_t *data, uint32_t dataLen, uint8_t **digest, uint32_t *digestLen) {

    int err, hash;
    hmac_state hmac;
    unsigned char dst[MAXBLOCKSIZE];
    unsigned long dstlen = 0;
    ltc_hash_descriptor hashDescriptor = {};
    const char *hashId = NULL;

    if (key == NULL || keyLen == 0 ||
            data == NULL || dataLen == 0 ||
            digest == NULL || digestLen == NULL){
        printf("HMAC_HASH param err.\n");
        return 1;
    }

    if (type != HMAC_MD5 && type != HMAC_SHA1 && type != HMAC_SHA256 && type != HMAC_SHA512){
        printf("HMAC_HASH type err.\n");
        return 1;
    }

    switch (type) {
        case HMAC_MD5:
            hashDescriptor = md5_desc;
            hashId = "md5";
            break;
        case HMAC_SHA1:
            hashDescriptor = sha1_desc;
            hashId = "sha1";
            break;
        case HMAC_SHA256:
            hashDescriptor = sha256_desc;
            hashId = "sha256";
            break;
        case HMAC_SHA512:
            hashDescriptor = sha512_desc;
            hashId = "sha512";
            break;
    }

    if (register_hash(&hashDescriptor) == -1) {
        printf("HMAC_SHA1 register_hash err.\n");
        return -1;
    }

    hash = find_hash(hashId);

    if ((err = hmac_init(&hmac, hash, key, keyLen)) != CRYPT_OK) {
        printf("HMAC_SHA1 hmac_init err: %s\n", error_to_string(err));
        return -1;
    }

    if((err = hmac_process(&hmac, data, dataLen)) != CRYPT_OK) {
        printf("HMAC_SHA1 hmac_process err: %s\n", error_to_string(err));
        return -1;
    }

    dstlen = sizeof(dst);
    if ((err = hmac_done(&hmac, dst, &dstlen)) != CRYPT_OK) {
        printf("HMAC_SHA1 hmac_done err: %s\n", error_to_string(err));
        return -1;
    }

    *digest = (uint8_t *)malloc(dstlen+1);
    if (*digest == NULL){
        printf("malloc err.\n");
        return 1;
    }

    memset(*digest, 0, dstlen+1);
    memcpy(*digest, dst, dstlen);

    *digestLen = (uint32_t)dstlen;

    return 0;
}
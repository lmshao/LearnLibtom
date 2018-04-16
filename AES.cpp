//
// Created by Liming Shao on 2018/4/11.
//

#include "AES.h"
#include <stdlib.h>
#include <tomcrypt.h>
#include "Utils.h"

int AES_Test() {
    unsigned char key[]="1234567890123456";
#if 01   // AES EBC Enc
    const char *pt = "hello";
    uint8_t *ct = NULL;
    uint32_t cl = 0;
    AES_ECB(key, sizeof(key)-1, (uint8_t*)pt, (uint32_t)strlen(pt), &ct, &cl, ENCRYPTION);
    printf("AES EBC plain:\t%s\n", pt);
    printf("AES EBC cipher:\t");
    for (int i = 0; i < cl; ++i) {
        printf("%02x", ct[i]);
    }
    printf("\n\n");
#endif

#if 01   // AES EBC Dec
    const char *i2Str = "efbcf25fd8d083039fe1f870fc250a7c";
    uint8_t *o2 = NULL;
    uint32_t o2L = 0;

    uint8_t *i2Byte = NULL;
    uint32_t i2ByteL = 0;
    Hex2Byte(i2Str, &i2Byte, &i2ByteL);
    printf("AES EBC Dec cipher:\t");
    for (int i = 0; i < i2ByteL; ++i) {
        printf("%02x", i2Byte[i]);
    }

    AES_ECB(key, sizeof(key)-1, i2Byte, (uint32_t)i2ByteL, &o2, &o2L, DECRYPTION);
    printf("AES EBC Dec plain:\t");
    for (int i = 0; i < o2L; ++i) {
        printf("%c", o2[i]);
    }
    printf("\n\n");
#endif

    return 0;
}

int AES_ECB(const uint8_t *key, uint32_t keyLen, const uint8_t *inData, uint32_t inLen,
                uint8_t **outData, uint32_t *outLen, CryptoOperation crypto) {

    uint8_t *iData = NULL;
    uint32_t len = 0;
    uint8_t *oData = NULL;
    uint8_t actualKey[32] = {0};
    symmetric_ECB ecb;

    if (NULL == key || NULL == inData || NULL == outData || NULL == outLen) {
        printf("AES_ECB_Enc param is NULL.\n");
        return -1;
    }

    if (crypto != ENCRYPTION && crypto != DECRYPTION){
        printf("AES_ECB_Enc param crypto is wrong.");
        return -1;
    }

    if (keyLen > 16){
        printf("AES_ECB_Enc keyLen %d > 16.\n", keyLen);
        return -1;
    }

    // processing key
    memcpy(actualKey, key, keyLen);

    if (register_cipher(&aes_desc) < 0) {
        printf("AES_ECB_Enc register_cipher err.\n");
        return -1;
    }

    int idx = find_cipher("aes");
    if (idx == -1) {
        printf("AES_ECB_Enc find_cipher err.\n");
        return -1;
    }

    if (CRYPT_OK != ecb_start(idx, actualKey, cipher_descriptor[idx].min_key_length, 0, &ecb)) {
        printf("AES_ECB_Enc ecb_start err.\n");
        return -1;
    }

    printf("\nmin_key_length = %d\n", cipher_descriptor[idx].min_key_length);

    if (ENCRYPTION == crypto){
        // padding plain data
        if (AES_Padding(ZEROPADDING, inData, inLen, &iData, &len) != 0){
            printf("AES_ECB_Enc AES_Padding err.\n");
            return -1;
        }

        oData = (uint8_t*)malloc(len);
        if (NULL == oData){
            printf("AES_ECB_Enc malloc err.\n");
            return -1;
        }
        memset(oData, 0, len);

        if (CRYPT_OK != ecb_encrypt(iData, oData, len, &ecb)) {
            printf("AES_ECB_Enc ecb_encrypt err.\n");
            return -1;
        }
    }
    else {

        if (inLen%16){
            printf("AES_ECB param inLen is wrong.\n");
            return -1;
        }

        oData = (uint8_t*)malloc(inLen);
        if (NULL == oData){
            printf("AES_ECB malloc err.\n");
            return -1;
        }
        memset(oData, 0, inLen);

        if (CRYPT_OK != ecb_decrypt(inData, oData, inLen, &ecb)) {
            printf("AES_ECB ecb_decrypt error.\n");
            return -1;
        }

        uint8_t *tData = NULL;
        if (AES_UnPadding(ZEROPADDING, oData, inLen, &tData, &len)){
            return -1;
        }
        oData = tData;
    }

    if (CRYPT_OK != ecb_done(&ecb)) {
        printf("AES_ECB_Enc ecb_done err.\n");
        return -1;
    }

    *outData = oData;
    *outLen = len;

    return 0;
}

int AES_Padding(PaddingType type, const uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen) {

    int blockSize = 16; // 128 bits

    if (ZEROPADDING != type && PKCS7 !=type ){
        printf("AES_Padding PaddingType is wrong.\n");
        return -1;
    }

    if (NULL == in || NULL == out || NULL == outLen){
        printf("AES_Padding param is NULL.\n");
        return -1;
    }

    uint32_t buffLen = (inLen/blockSize + 1)*blockSize;
    uint8_t padValue = (uint8_t)(blockSize - (inLen%blockSize));

    uint8_t *buff = (uint8_t*)malloc((size_t)buffLen);

    if (ZEROPADDING == type){
        memset(buff, 0, buffLen);
        memcpy(buff, in, inLen);
    }

    if (PKCS7 == type){
        memset(buff, padValue, buffLen);
        memcpy(buff, in, inLen);
    }

    *out = buff;
    *outLen = buffLen;

    printf("AES_Padding inLen = %d, outLen = %d\n", inLen, buffLen);

    return 0;
}

int AES_UnPadding(PaddingType type, const uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen) {
    int blockSize = 16; // 128 bits

    if (ZEROPADDING != type && PKCS7 !=type ){
        printf("AES_Padding PaddingType is wrong.\n");
        return -1;
    }

    if (NULL == in || inLen < 16 || NULL == out || NULL == outLen){
        printf("AES_Padding param is NULL.\n");
        return -1;
    }

    if (0 != (inLen%blockSize)){
        printf("AES_Padding inLen is invalid.\n");
        return -1;
    }
    
    if (ZEROPADDING == type){
        for (int i = 0; i < blockSize; ++i) {
            if (*(in+inLen-1) != 0){
                break;
            }else{
                inLen--;
            }
        }
    }

    if (PKCS7 == type){
        uint8_t padValue = *(in+inLen-1);
        if (padValue > 0 && padValue <= 16){
            bool isPadding = true;
            for (int i = 0; i < padValue; ++i) {
                if (*(in+inLen-1-i) != padValue){
                    isPadding = false;
                    break;
                }
            }
            if (isPadding)
                inLen -= (int)padValue;
        }
    }

    *out = (uint8_t*)in;
    *outLen = inLen;

    printf("AES_Padding inLen = %d, outLen = %d\n", inLen, inLen);

    return 0;
}

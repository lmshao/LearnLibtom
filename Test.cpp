//
// Created by Liming Shao on 2018/4/17.
//

#include "Test.h"
#include <stdio.h>
#include <string.h>
#include "AES.h"

int AES_Test() {

    AES_ECB_Test();

    AES_CBC_Test();

    return 0;
}

int AES_ECB_Test() {
    printf("\nAES_ECB_Test\n");
    unsigned char key[]="1234567890123456";

    const char *pt = "Advanced Encryption Standard, ECB.";
    uint8_t *ct = NULL, *ot = NULL;
    uint32_t cl = 0, ol = 0;

    PaddingType type = PKCS7;
//    PaddingType type = ZEROPADDING;

    AES_ECB(key, sizeof(key)-1, (uint8_t*)pt, (uint32_t)strlen(pt), &ct, &cl, ENCRYPTION, type);
    AES_ECB(key, sizeof(key)-1, ct, cl, &ot, &ol, DECRYPTION, type);

    printf("AES EBC plain before enc:\t%s\n", (char*)pt);
    printf("AES ECB cipher data HEX:\t%s\n", toHex(ct, cl));
    printf("AES ECB cipher data Base64:\t%s\n", toBase64(ct, cl));
    printf("AES EBC plain after dec:\t%s\n", (char*)ot);

    return 0;
}

int AES_CBC_Test() {
    printf("\nAES_CBC_Test\n");
    unsigned char key[]="1234567890123456";
    unsigned char iv[]="abcdefghijklmnop";

    const char *pt = "Advanced Encryption Standard, CBC.";
    uint8_t *ct = NULL, *ot = NULL;
    uint32_t cl = 0, ol = 0;

    PaddingType type = PKCS7;
//    PaddingType type = ZEROPADDING;

    AES_CBC(key, sizeof(key)-1, iv, sizeof(iv)-1,(uint8_t*)pt,(uint32_t)strlen(pt), &ct, &cl, ENCRYPTION, type);
    AES_CBC(key, sizeof(key)-1, iv, sizeof(iv)-1, ct, cl, &ot, &ol, DECRYPTION, type);

    printf("AES CBC plain before enc:\t%s\n", (char*)pt);
    printf("AES CBC cipher data HEX:\t%s\n", toHex(ct, cl));
    printf("AES CBC cipher data Base64:\t%s\n", toBase64(ct, cl));
    printf("AES CBC plain after dec:\t%s\n", (char*)ot);

    return 0;
}

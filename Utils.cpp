//
// Created by Liming Shao on 2018/4/11.
//

#include "Utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int Byte2Hex(const uint8_t *in, int len, char **out) {
    if (in == NULL || len <= 0 || out == NULL){
        printf("Byte2Hex param err.\n");
        return 1;
    }

    int buffLen = len * 2 +1;
    char *buff = (char *)malloc(buffLen * sizeof(char));
    if (buff == NULL){
        printf("malloc err\n");
        return 1;
    }
    memset(buff, 0, (size_t)buffLen);

    for (int i = 0; i < len; ++i) {
        sprintf(buff+2*i, "%02x", *in++);
    }

    *out = buff;
    return 0;
}

static inline uint8_t getCharValue(char c){
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return (uint8_t)(c - 'a' + 10);
    }
    else if (c >= 'A' && c <= 'F') {
        return (uint8_t)(c - 'A' + 10);
    }
    else {
        printf("getCharValue invalid char: %c\n", c);
        return 0xff;
    }
}

int Hex2Byte(const char *in, uint8_t **out, uint32_t *len){
    if (NULL == in || NULL == out || NULL == len){
        printf("Hex2Byte param err.\n");
        return -1;
    }

    int inLen = (int)strlen(in);
    if (inLen%2) {
        printf("Hex2Byte len err.\n");
        return -1;
    }

    uint8_t *buff = (uint8_t *)malloc((size_t)inLen/2);
    if (buff == NULL){
        printf("malloc err\n");
        return 1;
    }
    memset(buff, 0, (size_t)inLen/2);

    for (int i = 0; i < inLen/2; ++i) {
        uint8_t h = getCharValue(*in++);
        uint8_t l = getCharValue(*in++);
        if (h == 0xff || l == 0xff){
            printf("Hex2Byte char is wrong.\n");
            free(buff);
            return -1;
        }

        buff[i] = (uint8_t)(((h << 4) & 0xF0) | l);
    }

    *out = buff;
    *len = inLen/2;
    return 0;
}

const char *Base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789+/";



int Base64Encrypt(const uint8_t *plain, uint32_t plainLen, char **base64) {
    int buffLen, n;
    char *pos;
    char *buff = NULL;

    if(plain == NULL || plainLen <= 0 || base64 == NULL){
        printf("Base64Encrypt param err.\n");
        return -1;
    }

    buffLen = (plainLen/3)*4 + ((plainLen%3)?4:0);
    buff = (char*)malloc(buffLen* sizeof(uint8_t)+1);
    if(buff == NULL){
        printf("malloc error.\n");
        return -1;
    }

    pos = buff;

    for (int i = 0; i < plainLen/3; ++i) {

        n = (plain[3*i] >> 2) & 0x3F;
        *pos++ = Base64Table[n];

        n = ((plain[3*i] << 4) & 0x30) | ((plain[3*i+1] >> 4) & 0x0F);
        *pos++ = Base64Table[n];

        n = ((plain[3*i+1]  << 2) & 0x3C) | ((plain[3*i+2] >> 6) & 0x03);
        *pos++ = Base64Table[n];

        n = plain[3*i+2] & 0x3F;
        *pos++ = Base64Table[n];
    }

    if(plainLen%3 != 0){
        n = (plain[(plainLen/3)*3] >> 2) & 0x3F;
        *pos++ = (uint8_t) Base64Table[n];

        if(plainLen%3 == 1){
            n = (plain[(plainLen/3)*3] << 4) & 0x30;
            *pos++ = (uint8_t) Base64Table[n];
            *pos++ = '=';
            *pos++ = '=';
        } else{
            n = (plain[(plainLen/3)*3]<< 4 & 0x30) | ((plain[(plainLen/3)*3+1]  >> 4) & 0x0F);
            *pos++ = (uint8_t) Base64Table[n];

            n = (plain[(plainLen/3)*3+1] << 2 ) & 0x3C;
            *pos++ = (uint8_t) Base64Table[n];
            *pos++ = '=';
        }
    }

    *pos = '\0';

    *base64 = buff;
    return 0;
}

static inline int getBase64TableIndex(char c) {
    int ret;
    if (c >= 'a' && c <= 'z'){
        ret =  c - 71;
    } else if (c >= 'A' && c <= 'Z'){
        ret = c - 65;
    } else if (c >= '0' && c <= '9'){
        ret = c + 4;
    } else if (c == '+'){
        ret = 62;
    } else if (c == '/'){
        ret = 63;
    } else if (c == '=') {
        ret = 0;
    } else {
        ret = -1;
    }

    return ret;
}

int Base64Decrypt(const char *base64, uint8_t **plain, uint32_t *plainLen) {
    int buffLen;
    uint8_t *buff = NULL, *pos;
    int cipherLen = (int)strlen(base64);

    if(base64 == NULL || plain == NULL || plainLen == NULL){
        printf("Base64Decrypt param err.\n");
        return -1;
    }

    if (cipherLen%4 != 0){
        printf("Base64Decrypt base64 cipher text length is wrong\n");
        return -1;
    }

    buffLen = cipherLen/4*3;
    buff = (uint8_t*)malloc(buffLen* sizeof(uint8_t)+1);
    if(buff == NULL){
        printf("malloc error.\n");
    }

    pos = buff;

    int arr[4] = {0};
    for (int i = 0; i < cipherLen/4; ++i) {
        for (int j = 0; j < 4; ++j) {
            arr[j] = getBase64TableIndex(base64[4*i+j]);
            if(arr[j] == -1){
                printf("Ciphertext is wrong\n");
                return -1;
            }
        }
        *pos++ = (uint8_t) (((arr[0] << 2) & 0xFC) | ((arr[1] >> 4) & 0x03));
        *pos++ = (uint8_t) (((arr[1] << 4) & 0xF0) | ((arr[2] >> 2) & 0x0F));
        *pos++ = (uint8_t) (((arr[2] << 6) & 0xC0) | (arr[3] & 0x3F));
    }
    *pos = '\0';

    *plain = buff;
    *plainLen = (int) strlen((const char *) buff);

    return 0;
}

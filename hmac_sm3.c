#include "simple_gmsm/hmac_sm3.h"

#include <string.h>

#define HMAC_SM3_BLOCK_SIZE 64
#define HMAC_SM3_DIGEST_SIZE 32

void hmac_sm3_init(hmac_sm3_context_t* ctx, const unsigned char* key,
                   unsigned long keylen) {
    unsigned char k[HMAC_SM3_BLOCK_SIZE];
    unsigned char pad[HMAC_SM3_BLOCK_SIZE];
    unsigned long i;

    memset(k, 0, HMAC_SM3_BLOCK_SIZE);

    if (keylen > HMAC_SM3_BLOCK_SIZE) {
        sm3(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }

    // inner = SM3(ipad || ...)
    for (i = 0; i < HMAC_SM3_BLOCK_SIZE; i++) {
        pad[i] = k[i] ^ 0x36;
    }
    sm3_init(&ctx->inner);
    sm3_update(&ctx->inner, pad, HMAC_SM3_BLOCK_SIZE);

    // outer = SM3(opad || ...)
    for (i = 0; i < HMAC_SM3_BLOCK_SIZE; i++) {
        pad[i] = k[i] ^ 0x5c;
    }
    sm3_init(&ctx->outer);
    sm3_update(&ctx->outer, pad, HMAC_SM3_BLOCK_SIZE);

    /* Wipe key material from stack */
    {
        volatile unsigned char *vk = (volatile unsigned char *)k;
        volatile unsigned char *vp = (volatile unsigned char *)pad;
        for (i = 0; i < HMAC_SM3_BLOCK_SIZE; i++) {
            vk[i] = 0;
            vp[i] = 0;
        }
    }
}

void hmac_sm3_update(hmac_sm3_context_t* ctx, const unsigned char* data,
                     unsigned long len) {
    sm3_update(&ctx->inner, data, len);
}

void hmac_sm3_finish(hmac_sm3_context_t* ctx, unsigned char mac[32]) {
    unsigned char inner_hash[HMAC_SM3_DIGEST_SIZE];

    sm3_finish(&ctx->inner, inner_hash);
    sm3_update(&ctx->outer, inner_hash, HMAC_SM3_DIGEST_SIZE);
    sm3_finish(&ctx->outer, mac);
}

void hmac_sm3(const unsigned char* key, unsigned long keylen,
              const unsigned char* data, unsigned long datalen,
              unsigned char mac[32]) {
    hmac_sm3_context_t ctx;

    hmac_sm3_init(&ctx, key, keylen);
    hmac_sm3_update(&ctx, data, datalen);
    hmac_sm3_finish(&ctx, mac);
}

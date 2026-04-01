#include "simple_gmsm/tlcp.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  TLCP PRF – TLS 1.2-style PRF using HMAC-SM3                      */
/*                                                                    */
/*  P_SM3(secret, seed) = HMAC_SM3(secret, A(1) + seed)              */
/*                      + HMAC_SM3(secret, A(2) + seed) + ...         */
/*  where A(0) = seed                                                 */
/*        A(i) = HMAC_SM3(secret, A(i-1))                            */
/*                                                                    */
/*  PRF(secret, label, seed) = P_SM3(secret, label + seed)            */
/* ------------------------------------------------------------------ */

#define SM3_DIGEST_LEN 32

void tlcp_prf(const unsigned char* secret, unsigned long secret_len,
              const char* label,
              const unsigned char* seed, unsigned long seed_len,
              unsigned char* out, unsigned long out_len) {
    unsigned long label_len = 0;
    unsigned char a[SM3_DIGEST_LEN]; /* A(i) */
    unsigned char p[SM3_DIGEST_LEN]; /* P_hash output block */
    unsigned long offset = 0;
    hmac_sm3_context_t hmac;

    /* Compute label length */
    if (label) {
        const char* s = label;
        while (*s++)
            label_len++;
    }

    /*
     * A(0) = label + seed
     * A(1) = HMAC_SM3(secret, A(0))
     */
    hmac_sm3_init(&hmac, secret, secret_len);
    if (label_len > 0)
        hmac_sm3_update(&hmac, (const unsigned char*)label, label_len);
    if (seed_len > 0)
        hmac_sm3_update(&hmac, seed, seed_len);
    hmac_sm3_finish(&hmac, a); /* A(1) */

    while (offset < out_len) {
        /*
         * P_hash block = HMAC_SM3(secret, A(i) + label + seed)
         */
        hmac_sm3_init(&hmac, secret, secret_len);
        hmac_sm3_update(&hmac, a, SM3_DIGEST_LEN);
        if (label_len > 0)
            hmac_sm3_update(&hmac, (const unsigned char*)label, label_len);
        if (seed_len > 0)
            hmac_sm3_update(&hmac, seed, seed_len);
        hmac_sm3_finish(&hmac, p);

        /* Copy bytes to output, possibly truncating the last block */
        unsigned long remaining = out_len - offset;
        unsigned long chunk = remaining < SM3_DIGEST_LEN ? remaining : SM3_DIGEST_LEN;
        memcpy(out + offset, p, chunk);
        offset += chunk;

        /* A(i+1) = HMAC_SM3(secret, A(i)) */
        hmac_sm3_init(&hmac, secret, secret_len);
        hmac_sm3_update(&hmac, a, SM3_DIGEST_LEN);
        hmac_sm3_finish(&hmac, a);
    }
}

/* ------------------------------------------------------------------ */
/*  Master secret derivation                                          */
/*  master_secret = PRF(pre_master_secret, "master secret",           */
/*                      client_random + server_random)[0..47]         */
/* ------------------------------------------------------------------ */

void tlcp_derive_master_secret(unsigned char master_secret[48],
                               const unsigned char* pre_master_secret,
                               unsigned long pms_len,
                               const unsigned char client_random[32],
                               const unsigned char server_random[32]) {
    unsigned char seed[64]; /* client_random(32) + server_random(32) */

    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);

    tlcp_prf(pre_master_secret, pms_len,
             "master secret",
             seed, 64,
             master_secret, TLCP_MASTER_SECRET_LEN);
}

/* ------------------------------------------------------------------ */
/*  Key expansion                                                     */
/*  key_block = PRF(master_secret, "key expansion",                   */
/*                  server_random + client_random)                    */
/*                                                                    */
/*  Split into:                                                       */
/*    client_write_mac_key (32)                                       */
/*    server_write_mac_key (32)                                       */
/*    client_write_key     (16)                                       */
/*    server_write_key     (16)                                       */
/*    client_write_iv      (16)                                       */
/*    server_write_iv      (16)                                       */
/*  Total: 128 bytes                                                  */
/*                                                                    */
/*  Note: for GCM suites, MAC keys are unused and IVs are 4 bytes    */
/*  (implicit nonce), but we generate all 128 bytes for uniformity.   */
/* ------------------------------------------------------------------ */

#define KEY_BLOCK_LEN 128

void tlcp_derive_keys(tlcp_security_params_t* params) {
    unsigned char seed[64]; /* server_random(32) + client_random(32) */
    unsigned char key_block[KEY_BLOCK_LEN];
    unsigned long off = 0;

    /* Note: key expansion uses server_random first, then client_random */
    memcpy(seed, params->server_random, 32);
    memcpy(seed + 32, params->client_random, 32);

    tlcp_prf(params->master_secret, TLCP_MASTER_SECRET_LEN,
             "key expansion",
             seed, 64,
             key_block, KEY_BLOCK_LEN);

    /* Split key block */
    memcpy(params->client_write_mac_key, key_block + off, 32); off += 32;
    memcpy(params->server_write_mac_key, key_block + off, 32); off += 32;
    memcpy(params->client_write_key,     key_block + off, 16); off += 16;
    memcpy(params->server_write_key,     key_block + off, 16); off += 16;
    memcpy(params->client_write_iv,      key_block + off, 16); off += 16;
    memcpy(params->server_write_iv,      key_block + off, 16);

    /* Determine if cipher suite uses GCM mode */
    params->is_gcm = (params->cipher_suite == TLCP_ECC_SM4_GCM_SM3 ||
                      params->cipher_suite == TLCP_ECDHE_SM4_GCM_SM3) ? 1 : 0;
}

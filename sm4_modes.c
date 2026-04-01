#include "simple_gmsm/sm4.h"

#include "endian.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  CBC Mode                                                          */
/* ------------------------------------------------------------------ */

int sm4_cbc_encrypt(const unsigned char* key, const unsigned char* iv,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned long* outlen) {
    SM4_KEY ks;
    unsigned char block[SM4_BLOCK_SIZE];
    unsigned char prev[SM4_BLOCK_SIZE];
    unsigned long i, nblocks;
    unsigned char pad;

    sm4_set_key(key, &ks);
    memcpy(prev, iv, SM4_BLOCK_SIZE);

    /* PKCS#7: pad value = 16 - (inlen % 16), always at least 1 byte */
    pad = (unsigned char)(SM4_BLOCK_SIZE - (inlen % SM4_BLOCK_SIZE));
    nblocks = (inlen / SM4_BLOCK_SIZE) + 1;
    *outlen = nblocks * SM4_BLOCK_SIZE;

    for (i = 0; i < nblocks; i++) {
        unsigned long offset = i * SM4_BLOCK_SIZE;
        unsigned long remaining = inlen - (i * SM4_BLOCK_SIZE);

        if (remaining >= SM4_BLOCK_SIZE) {
            /* Full plaintext block */
            for (unsigned long j = 0; j < SM4_BLOCK_SIZE; j++)
                block[j] = in[offset + j] ^ prev[j];
        } else {
            /* Last block with padding */
            unsigned long j;
            for (j = 0; j < remaining; j++)
                block[j] = in[offset + j] ^ prev[j];
            for (; j < SM4_BLOCK_SIZE; j++)
                block[j] = pad ^ prev[j];
        }

        sm4_encrypt(block, out + offset, &ks);
        memcpy(prev, out + offset, SM4_BLOCK_SIZE);
    }

    return 1;
}

int sm4_cbc_decrypt(const unsigned char* key, const unsigned char* iv,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned long* outlen) {
    SM4_KEY ks;
    unsigned char block[SM4_BLOCK_SIZE];
    const unsigned char* prev;
    unsigned long i, nblocks;
    unsigned char pad, valid;

    if (inlen == 0 || (inlen % SM4_BLOCK_SIZE) != 0)
        return 0;

    sm4_set_key(key, &ks);
    nblocks = inlen / SM4_BLOCK_SIZE;

    for (i = 0; i < nblocks; i++) {
        unsigned long offset = i * SM4_BLOCK_SIZE;
        prev = (i == 0) ? iv : (in + offset - SM4_BLOCK_SIZE);

        sm4_decrypt(in + offset, block, &ks);
        for (unsigned long j = 0; j < SM4_BLOCK_SIZE; j++)
            out[offset + j] = block[j] ^ prev[j];
    }

    /* Validate and remove PKCS#7 padding */
    pad = out[inlen - 1];
    if (pad == 0 || pad > SM4_BLOCK_SIZE)
        return 0;

    valid = 1;
    for (unsigned long j = 0; j < pad; j++) {
        if (out[inlen - 1 - j] != pad)
            valid = 0;
    }
    if (!valid)
        return 0;

    *outlen = inlen - pad;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  CTR Mode                                                          */
/* ------------------------------------------------------------------ */

static void ctr_inc128(unsigned char ctr[SM4_BLOCK_SIZE]) {
    /* Increment 128-bit big-endian counter */
    for (int i = SM4_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++ctr[i] != 0)
            break;
    }
}

void sm4_ctr_encrypt(const unsigned char* key, const unsigned char* nonce,
                     const unsigned char* in, unsigned long len,
                     unsigned char* out) {
    SM4_KEY ks;
    unsigned char counter[SM4_BLOCK_SIZE];
    unsigned char keystream[SM4_BLOCK_SIZE];
    unsigned long offset = 0;

    sm4_set_key(key, &ks);
    memcpy(counter, nonce, SM4_BLOCK_SIZE);

    while (offset < len) {
        unsigned long chunk = len - offset;
        if (chunk > SM4_BLOCK_SIZE)
            chunk = SM4_BLOCK_SIZE;

        sm4_encrypt(counter, keystream, &ks);
        for (unsigned long i = 0; i < chunk; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        ctr_inc128(counter);
        offset += chunk;
    }
}

/* ------------------------------------------------------------------ */
/*  GCM Mode                                                          */
/* ------------------------------------------------------------------ */

/* GF(2^128) multiplication: V = V * Y
 * Polynomial: x^128 + x^7 + x^2 + x + 1 (0xE1000...0) */
static void gf128_mul(unsigned char X[16], const unsigned char Y[16]) {
    unsigned char V[16];
    unsigned char Z[16] = {0};

    memcpy(V, Y, 16);

    for (int i = 0; i < 128; i++) {
        /* If bit i of X is set, Z ^= V */
        if (X[i / 8] & (1 << (7 - (i % 8)))) {
            for (int j = 0; j < 16; j++)
                Z[j] ^= V[j];
        }

        /* Check if LSB of V is set (for reduction) */
        int lsb = V[15] & 1;

        /* Right-shift V by 1 */
        for (int j = 15; j > 0; j--)
            V[j] = (V[j] >> 1) | (V[j - 1] << 7);
        V[0] >>= 1;

        /* If lsb was set, XOR with R = 0xE1000...0 */
        if (lsb)
            V[0] ^= 0xE1;
    }

    memcpy(X, Z, 16);
}

/* GHASH: compute GHASH(H, aad, data) */
static void ghash(const unsigned char H[16],
                  const unsigned char* aad, unsigned long aadlen,
                  const unsigned char* data, unsigned long datalen,
                  unsigned char out[16]) {
    unsigned char X[16] = {0};
    unsigned char block[16];
    unsigned long i, nblocks;

    /* Process AAD */
    nblocks = aadlen / 16;
    for (i = 0; i < nblocks; i++) {
        for (int j = 0; j < 16; j++)
            X[j] ^= aad[i * 16 + j];
        gf128_mul(X, H);
    }
    if (aadlen % 16) {
        memset(block, 0, 16);
        memcpy(block, aad + nblocks * 16, aadlen % 16);
        for (int j = 0; j < 16; j++)
            X[j] ^= block[j];
        gf128_mul(X, H);
    }

    /* Process data (ciphertext) */
    nblocks = datalen / 16;
    for (i = 0; i < nblocks; i++) {
        for (int j = 0; j < 16; j++)
            X[j] ^= data[i * 16 + j];
        gf128_mul(X, H);
    }
    if (datalen % 16) {
        memset(block, 0, 16);
        memcpy(block, data + nblocks * 16, datalen % 16);
        for (int j = 0; j < 16; j++)
            X[j] ^= block[j];
        gf128_mul(X, H);
    }

    /* Final block: [len(A) in bits || len(C) in bits] as 64-bit big-endian */
    memset(block, 0, 16);
    {
        unsigned long long aad_bits = (unsigned long long)aadlen * 8;
        unsigned long long data_bits = (unsigned long long)datalen * 8;
        block[0]  = (unsigned char)(aad_bits >> 56);
        block[1]  = (unsigned char)(aad_bits >> 48);
        block[2]  = (unsigned char)(aad_bits >> 40);
        block[3]  = (unsigned char)(aad_bits >> 32);
        block[4]  = (unsigned char)(aad_bits >> 24);
        block[5]  = (unsigned char)(aad_bits >> 16);
        block[6]  = (unsigned char)(aad_bits >> 8);
        block[7]  = (unsigned char)(aad_bits);
        block[8]  = (unsigned char)(data_bits >> 56);
        block[9]  = (unsigned char)(data_bits >> 48);
        block[10] = (unsigned char)(data_bits >> 40);
        block[11] = (unsigned char)(data_bits >> 32);
        block[12] = (unsigned char)(data_bits >> 24);
        block[13] = (unsigned char)(data_bits >> 16);
        block[14] = (unsigned char)(data_bits >> 8);
        block[15] = (unsigned char)(data_bits);
    }
    for (int j = 0; j < 16; j++)
        X[j] ^= block[j];
    gf128_mul(X, H);

    memcpy(out, X, 16);
}

/* Increment last 32 bits of counter block (GCM spec: inc_32) */
static void gcm_inc32(unsigned char ctr[16]) {
    unsigned int c;
    GETU32(c, ctr, 12);
    c++;
    PUTU32(c, ctr, 12);
}

/* GCM CTR encryption (uses inc_32 per NIST SP 800-38D) */
static void gcm_ctr_encrypt(const SM4_KEY* ks,
                            const unsigned char* counter0,
                            const unsigned char* in, unsigned long len,
                            unsigned char* out) {
    unsigned char counter[16];
    unsigned char keystream[16];
    unsigned long offset = 0;

    memcpy(counter, counter0, 16);
    gcm_inc32(counter); /* Start from J0 + 1 */

    while (offset < len) {
        unsigned long chunk = len - offset;
        if (chunk > 16)
            chunk = 16;

        sm4_encrypt(counter, keystream, ks);
        for (unsigned long i = 0; i < chunk; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        gcm_inc32(counter);
        offset += chunk;
    }
}

/* Constant-time comparison */
static int ct_memcmp(const unsigned char* a, const unsigned char* b,
                     unsigned long len) {
    unsigned char diff = 0;
    for (unsigned long i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return (diff == 0) ? 0 : 1;
}

int sm4_gcm_encrypt(const unsigned char* key,
                    const unsigned char* iv, unsigned long ivlen,
                    const unsigned char* aad, unsigned long aadlen,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned char tag[16]) {
    SM4_KEY ks;
    unsigned char H[16] = {0};
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char enc_j0[16];

    sm4_set_key(key, &ks);

    /* H = SM4_encrypt(0^128) */
    sm4_encrypt(H, H, &ks);

    /* Compute J0 */
    if (ivlen == 12) {
        memcpy(J0, iv, 12);
        J0[12] = 0;
        J0[13] = 0;
        J0[14] = 0;
        J0[15] = 1;
    } else {
        ghash(H, NULL, 0, iv, ivlen, J0);
    }

    /* Encrypt plaintext with CTR starting from J0+1 */
    gcm_ctr_encrypt(&ks, J0, in, inlen, out);

    /* tag = GHASH(H, aad, ciphertext) XOR SM4_encrypt(J0) */
    ghash(H, aad, aadlen, out, inlen, S);
    sm4_encrypt(J0, enc_j0, &ks);
    for (int i = 0; i < 16; i++)
        tag[i] = S[i] ^ enc_j0[i];

    return 1;
}

int sm4_gcm_decrypt(const unsigned char* key,
                    const unsigned char* iv, unsigned long ivlen,
                    const unsigned char* aad, unsigned long aadlen,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, const unsigned char tag[16]) {
    SM4_KEY ks;
    unsigned char H[16] = {0};
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char enc_j0[16];
    unsigned char computed_tag[16];

    sm4_set_key(key, &ks);

    /* H = SM4_encrypt(0^128) */
    sm4_encrypt(H, H, &ks);

    /* Compute J0 */
    if (ivlen == 12) {
        memcpy(J0, iv, 12);
        J0[12] = 0;
        J0[13] = 0;
        J0[14] = 0;
        J0[15] = 1;
    } else {
        ghash(H, NULL, 0, iv, ivlen, J0);
    }

    /* Verify tag before decrypting */
    ghash(H, aad, aadlen, in, inlen, S);
    sm4_encrypt(J0, enc_j0, &ks);
    for (int i = 0; i < 16; i++)
        computed_tag[i] = S[i] ^ enc_j0[i];

    if (ct_memcmp(computed_tag, tag, 16) != 0) {
        memset(out, 0, inlen);
        return 0;
    }

    /* Decrypt ciphertext with CTR starting from J0+1 */
    gcm_ctr_encrypt(&ks, J0, in, inlen, out);

    return 1;
}

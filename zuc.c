#include "simple_gmsm/zuc.h"

#include <stdlib.h>
#include <string.h>

/* ZUC S-box S0 (from the specification) */
static const unsigned char S0[256] = {
    0x3E,0x72,0x5B,0x47,0xCA,0xE0,0x00,0x33,0x04,0xD1,0x54,0x98,0x09,0xB9,0x6D,0xCB,
    0x7B,0x1B,0xF9,0x32,0xAF,0x9D,0x6A,0xA5,0xB8,0x2D,0xFC,0x1D,0x08,0x53,0x03,0x90,
    0x4D,0x4E,0x84,0x99,0xE4,0xCE,0xD9,0x91,0xDD,0xB6,0x85,0x48,0x8B,0x29,0x6E,0xAC,
    0xCD,0xC1,0xF8,0x1E,0x73,0x43,0x69,0xC6,0xB5,0xBD,0xFD,0x39,0x63,0x20,0xD4,0x38,
    0x76,0x7D,0xB2,0xA7,0xCF,0xED,0x57,0xC5,0xF3,0x2C,0xBB,0x14,0x21,0x06,0x55,0x9B,
    0xE3,0xEF,0x5E,0x31,0x4F,0x7F,0x5A,0xA4,0x0D,0x82,0x51,0x49,0x5F,0xBA,0x58,0x1C,
    0x4A,0x16,0xD5,0x17,0xA8,0x92,0x24,0x1F,0x8C,0xFF,0xD8,0xAE,0x2E,0x01,0xD3,0xAD,
    0x3B,0x4B,0xDA,0x46,0xEB,0xC9,0xDE,0x9A,0x8F,0x87,0xD7,0x3A,0x80,0x6F,0x2F,0xC8,
    0xB1,0xB4,0x37,0xF7,0x0A,0x22,0x13,0x28,0x7C,0xCC,0x3C,0x89,0xC7,0xC3,0x96,0x56,
    0x07,0xBF,0x7E,0xF0,0x0B,0x2B,0x97,0x52,0x35,0x41,0x79,0x61,0xA6,0x4C,0x10,0xFE,
    0xBC,0x26,0x95,0x88,0x8A,0xB0,0xA3,0xFB,0xC0,0x18,0x94,0xF2,0xE1,0xE5,0xE9,0x5D,
    0xD0,0xDC,0x11,0x66,0x64,0x5C,0xEC,0x59,0x42,0x75,0x12,0xF5,0x74,0x9C,0xAA,0x23,
    0x0E,0x86,0xAB,0xBE,0x2A,0x02,0xE7,0x67,0xE6,0x44,0xA2,0x6C,0xC2,0x93,0x9F,0xF1,
    0xF6,0xFA,0x36,0xD2,0x50,0x68,0x9E,0x62,0x71,0x15,0x3D,0xD6,0x40,0xC4,0xE2,0x0F,
    0x8E,0x83,0x77,0x6B,0x25,0x05,0x3F,0x0C,0x30,0xEA,0x70,0xB7,0xA1,0xE8,0xA9,0x65,
    0x8D,0x27,0x1A,0xDB,0x81,0xB3,0xA0,0xF4,0x45,0x7A,0x19,0xDF,0xEE,0x78,0x34,0x60
};

/* ZUC S-box S1 (from the specification) */
static const unsigned char S1[256] = {
    0x55,0xC2,0x63,0x71,0x3B,0xC8,0x47,0x86,0x9F,0x3C,0xDA,0x5B,0x29,0xAA,0xFD,0x77,
    0x8C,0xC5,0x94,0x0C,0xA6,0x1A,0x13,0x00,0xE3,0xA8,0x16,0x72,0x40,0xF9,0xF8,0x42,
    0x44,0x26,0x68,0x96,0x81,0xD9,0x45,0x3E,0x10,0x76,0xC6,0xA7,0x8B,0x39,0x43,0xE1,
    0x3A,0xB5,0x56,0x2A,0xC0,0x6D,0xB3,0x05,0x22,0x66,0xBF,0xDC,0x0B,0xFA,0x62,0x48,
    0xDD,0x20,0x11,0x06,0x36,0xC9,0xC1,0xCF,0xF6,0x27,0x52,0xBB,0x69,0xF5,0xD4,0x87,
    0x7F,0x84,0x4C,0xD2,0x9C,0x57,0xA4,0xBC,0x4F,0x9A,0xDF,0xFE,0xD6,0x8D,0x7A,0xEB,
    0x2B,0x53,0xD8,0x5C,0xA1,0x14,0x17,0xFB,0x23,0xD5,0x7D,0x30,0x67,0x73,0x08,0x09,
    0xEE,0xB7,0x70,0x3F,0x61,0xB2,0x19,0x8E,0x4E,0xE5,0x4B,0x93,0x8F,0x5D,0xDB,0xA9,
    0xAD,0xF1,0xAE,0x2E,0xCB,0x0D,0xFC,0xF4,0x2D,0x46,0x6E,0x1D,0x97,0xE8,0xD1,0xE9,
    0x4D,0x37,0xA5,0x75,0x5E,0x83,0x9E,0xAB,0x82,0x9D,0xB9,0x1C,0xE0,0xCD,0x49,0x89,
    0x01,0xB6,0xBD,0x58,0x24,0xA2,0x5F,0x38,0x78,0x99,0x15,0x90,0x50,0xB8,0x95,0xE4,
    0xD0,0x91,0xC7,0xCE,0xED,0x0F,0xB4,0x6F,0xA0,0xCC,0xF0,0x02,0x4A,0x79,0xC3,0xDE,
    0xA3,0xEF,0xEA,0x51,0xE6,0x6B,0x18,0xEC,0x1B,0x2C,0x80,0xF7,0x74,0xE7,0xFF,0x21,
    0x5A,0x6A,0x54,0x1E,0x41,0x31,0x92,0x35,0xC4,0x33,0x07,0x0A,0xBA,0x7E,0x0E,0x34,
    0x88,0xB1,0x98,0x7C,0xF3,0x3D,0x60,0x6C,0x7B,0xCA,0xD3,0x1F,0x32,0x65,0x04,0x28,
    0x64,0xBE,0x85,0x9B,0x2F,0x59,0x8A,0xD7,0xB0,0x25,0xAC,0xAF,0x12,0x03,0xE2,0xF2
};

/* d constants for LFSR key loading (15-bit values from spec Table 3.4-1) */
static const unsigned int EK_d[16] = {
    0x44D7, 0x26BC, 0x626B, 0x135E,
    0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1,
    0x5E26, 0x3C4D, 0x789A, 0x47AC
};

/* ------- Modular arithmetic over GF(2^31-1) ------- */

static unsigned int add_mod31(unsigned int a, unsigned int b) {
    unsigned int c = a + b;
    return (c & 0x7FFFFFFFU) + (c >> 31);
}

/* Multiply by 2^n mod (2^31-1): circular left rotation of 31-bit value */
static unsigned int rot31(unsigned int a, unsigned int n) {
    return ((a << n) | (a >> (31 - n))) & 0x7FFFFFFFU;
}

/* ------- LFSR ------- */

static unsigned int lfsr_feedback(const unsigned int *s) {
    unsigned int f;
    f = s[0];
    f = add_mod31(f, rot31(s[0], 8));
    f = add_mod31(f, rot31(s[4], 20));
    f = add_mod31(f, rot31(s[10], 21));
    f = add_mod31(f, rot31(s[13], 17));
    f = add_mod31(f, rot31(s[15], 15));
    return f;
}

static void lfsr_shift(unsigned int *s, unsigned int f) {
    s[0]  = s[1];  s[1]  = s[2];  s[2]  = s[3];  s[3]  = s[4];
    s[4]  = s[5];  s[5]  = s[6];  s[6]  = s[7];  s[7]  = s[8];
    s[8]  = s[9];  s[9]  = s[10]; s[10] = s[11]; s[11] = s[12];
    s[12] = s[13]; s[13] = s[14]; s[14] = s[15]; s[15] = f;
}

static void lfsr_with_init_mode(zuc_state_t *state, unsigned int u) {
    unsigned int f = add_mod31(lfsr_feedback(state->lfsr), u);
    if (f == 0)
        f = 0x7FFFFFFFU;
    lfsr_shift(state->lfsr, f);
}

static void lfsr_with_work_mode(zuc_state_t *state) {
    unsigned int f = lfsr_feedback(state->lfsr);
    if (f == 0)
        f = 0x7FFFFFFFU;
    lfsr_shift(state->lfsr, f);
}

/* ------- Bit Reorganization ------- */

static void bit_reorganization(zuc_state_t *state) {
    const unsigned int *s = state->lfsr;
    state->x[0] = ((s[15] & 0x7FFF8000U) << 1) | (s[14] & 0xFFFFU);
    state->x[1] = ((s[11] & 0xFFFFU) << 16)     | (s[9]  >> 15);
    state->x[2] = ((s[7]  & 0xFFFFU) << 16)     | (s[5]  >> 15);
    state->x[3] = ((s[2]  & 0xFFFFU) << 16)     | (s[0]  >> 15);
}

/* ------- F function ------- */

static unsigned int rotl32(unsigned int x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

static unsigned int L1(unsigned int x) {
    return x ^ rotl32(x, 2) ^ rotl32(x, 10) ^ rotl32(x, 18) ^ rotl32(x, 24);
}

static unsigned int L2(unsigned int x) {
    return x ^ rotl32(x, 8) ^ rotl32(x, 14) ^ rotl32(x, 22) ^ rotl32(x, 30);
}

static unsigned int F(zuc_state_t *state) {
    unsigned int W, W1, W2, u, v;

    W  = (state->x[0] ^ state->r1) + state->r2;
    W1 = state->r1 + state->x[1];
    W2 = state->r2 ^ state->x[2];

    u = L1((W1 << 16) | (W2 >> 16));
    v = L2((W2 << 16) | (W1 >> 16));

    state->r1 = ((unsigned int)S0[u >> 24]          << 24) |
                ((unsigned int)S1[(u >> 16) & 0xFF]  << 16) |
                ((unsigned int)S0[(u >> 8)  & 0xFF]  <<  8) |
                 (unsigned int)S1[u & 0xFF];

    state->r2 = ((unsigned int)S0[v >> 24]          << 24) |
                ((unsigned int)S1[(v >> 16) & 0xFF]  << 16) |
                ((unsigned int)S0[(v >> 8)  & 0xFF]  <<  8) |
                 (unsigned int)S1[v & 0xFF];

    return W;
}

/* ------- Public API ------- */

void zuc_init(zuc_state_t *state, const unsigned char key[16],
              const unsigned char iv[16]) {
    int i;
    unsigned int w;

    /* Key loading */
    for (i = 0; i < 16; i++)
        state->lfsr[i] = ((unsigned int)key[i] << 23) | (EK_d[i] << 8) | iv[i];

    state->r1 = 0;
    state->r2 = 0;

    /* 32 initialization rounds */
    for (i = 0; i < 32; i++) {
        bit_reorganization(state);
        w = F(state);
        lfsr_with_init_mode(state, w >> 1);
    }

    /* One working-mode round, discard the output */
    bit_reorganization(state);
    F(state);
    lfsr_with_work_mode(state);
}

unsigned int zuc_generate(zuc_state_t *state) {
    unsigned int z;
    bit_reorganization(state);
    z = F(state) ^ state->x[3];
    lfsr_with_work_mode(state);
    return z;
}

void zuc_generate_keystream(zuc_state_t *state, unsigned int *keystream,
                            unsigned long nwords) {
    unsigned long i;
    for (i = 0; i < nwords; i++)
        keystream[i] = zuc_generate(state);
}

/* ------- 128-EEA3 ------- */

void zuc_eea3(const unsigned char key[16], unsigned int count,
              unsigned int bearer, unsigned int direction,
              const unsigned char *input, unsigned char *output,
              unsigned int bitlen) {
    zuc_state_t state;
    unsigned char iv[16];
    unsigned int nwords, i, z, remaining;

    /* Form IV per 3GPP TS 35.222 */
    iv[0]  = (unsigned char)(count >> 24);
    iv[1]  = (unsigned char)(count >> 16);
    iv[2]  = (unsigned char)(count >> 8);
    iv[3]  = (unsigned char)(count);
    iv[4]  = (unsigned char)(((bearer << 3) | ((direction & 1) << 2)) & 0xFC);
    iv[5]  = 0;
    iv[6]  = 0;
    iv[7]  = 0;
    iv[8]  = iv[0];
    iv[9]  = iv[1];
    iv[10] = iv[2];
    iv[11] = iv[3];
    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = iv[6];
    iv[15] = iv[7];

    zuc_init(&state, key, iv);

    nwords = (bitlen + 31) / 32;
    remaining = bitlen;

    for (i = 0; i < nwords; i++) {
        z = zuc_generate(&state);

        if (remaining >= 32) {
            output[4*i]     = input[4*i]     ^ (unsigned char)(z >> 24);
            output[4*i + 1] = input[4*i + 1] ^ (unsigned char)(z >> 16);
            output[4*i + 2] = input[4*i + 2] ^ (unsigned char)(z >> 8);
            output[4*i + 3] = input[4*i + 3] ^ (unsigned char)(z);
            remaining -= 32;
        } else {
            unsigned int nbytes = (remaining + 7) / 8;
            unsigned int j;
            for (j = 0; j < nbytes; j++)
                output[4*i + j] = input[4*i + j] ^
                                   (unsigned char)(z >> (24 - j * 8));
            if (remaining % 8) {
                unsigned int last = 4*i + nbytes - 1;
                unsigned char mask =
                    (unsigned char)(0xFFU << (8 - (remaining % 8)));
                output[last] = (output[last] & mask) |
                               (input[last] & (unsigned char)~mask);
            }
            remaining = 0;
        }
    }
}

/* ------- 128-EIA3 ------- */

/* Get bit i from byte array M (MSB first within each byte) */
static unsigned int get_bit(const unsigned char *data, unsigned int i) {
    return (data[i / 8] >> (7 - (i % 8))) & 1;
}

/* Get a 32-bit word starting at bit position i in the u32 keystream array */
static unsigned int get_word(const unsigned int *z, unsigned int i) {
    unsigned int word_idx = i / 32;
    unsigned int bit_off  = i % 32;
    if (bit_off == 0)
        return z[word_idx];
    return (z[word_idx] << bit_off) | (z[word_idx + 1] >> (32 - bit_off));
}

unsigned int zuc_eia3(const unsigned char key[16], unsigned int count,
                      unsigned int bearer, unsigned int direction,
                      const unsigned char *message, unsigned int bitlen) {
    zuc_state_t state;
    unsigned char iv[16];
    unsigned int nwords, i, T;
    unsigned int *z;

    /* Form IV per 3GPP TS 35.223 */
    iv[0]  = (unsigned char)(count >> 24);
    iv[1]  = (unsigned char)(count >> 16);
    iv[2]  = (unsigned char)(count >> 8);
    iv[3]  = (unsigned char)(count);
    iv[4]  = (unsigned char)((bearer << 3) & 0xF8);
    iv[5]  = 0;
    iv[6]  = 0;
    iv[7]  = 0;
    iv[8]  = (unsigned char)(((count >> 24) & 0xFF) ^ ((direction & 1) << 7));
    iv[9]  = (unsigned char)(count >> 16);
    iv[10] = (unsigned char)(count >> 8);
    iv[11] = (unsigned char)(count);
    iv[12] = iv[4];
    iv[13] = iv[5];
    iv[14] = (unsigned char)(iv[6] ^ ((direction & 1) << 7));
    iv[15] = iv[7];

    zuc_init(&state, key, iv);

    /* Need ceil((bitlen + 64) / 32) keystream words */
    nwords = (bitlen + 64 + 31) / 32;
    z = (unsigned int *)malloc(nwords * sizeof(unsigned int));
    if (!z)
        return 0;

    zuc_generate_keystream(&state, z, nwords);

    T = 0;
    for (i = 0; i < bitlen; i++) {
        if (get_bit(message, i))
            T ^= get_word(z, i);
    }
    T ^= get_word(z, bitlen);
    T ^= z[nwords - 1];

    free(z);
    return T;
}

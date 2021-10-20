#include "simple_gmsm/sm3.h"

#include "endian.h"


// 布尔函数
// 式中X,Y,Z 为字 (32比特)
#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF1(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// 循环左移
#define ROTL(X, n) (((X) << n) | ((X) >> (32 - n)))

// 置换函数
// 式中X为字 (32比特)
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

void sm3_init(sm3_context_t* ctx) {
    // 初始值
    ctx->digest[0] = 0x7380166F;
    ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7;
    ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC;
    ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D;
    ctx->digest[7] = 0xB0FB0E4E;
    ctx->length = 0;
    ctx->unhandle_len = 0;
}

static unsigned long sm3_update_block(sm3_context_t* ctx,
                                      const unsigned char* data,
                                      unsigned long len) {
    unsigned long i = 0, j;
    unsigned int W[68], W1[64], SS1, SS2, TT1, TT2;
    unsigned int Temp1, Temp2, Temp3, Temp4, Temp5;

    unsigned int A, B, C, D, E, F, G, H;

    if (len < 64) {
        return 0;
    }

    for (i = 0; i + 64 <= len; i += 64) {
        for (j = 0; j < 16; j++) {
            GETU32(W[j], data, i + 4 * j)
        }
        for (j = 16; j < 68; j++) {
            // W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^
            //       ROTL(W[j - 13], 7) ^ W[j - 6];
            // Why thd release's result is different with the debug's ?
            // Below is okay. Interesting, Perhaps VC6 has a bug of
            // Optimizaiton.
            Temp1 = W[j - 16] ^ W[j - 9];
            Temp2 = ROTL(W[j - 3], 15);
            Temp3 = Temp1 ^ Temp2;
            Temp4 = P1(Temp3);
            Temp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
            W[j] = Temp4 ^ Temp5;
        }
        for (j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        A = ctx->digest[0];
        B = ctx->digest[1];
        C = ctx->digest[2];
        D = ctx->digest[3];
        E = ctx->digest[4];
        F = ctx->digest[5];
        G = ctx->digest[6];
        H = ctx->digest[7];
        for (j = 0; j < 16; j++) {
            SS1 = ROTL((ROTL(A, 12) + E + ROTL(0x79cc4519, j)), 7);
            SS2 = SS1 ^ ROTL(A, 12);
            TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }
        for (j = 16; j < 64; j++) {
            SS1 = ROTL((ROTL(A, 12) + E + ROTL(0x7A879D8A, j)), 7);
            SS2 = SS1 ^ ROTL(A, 12);
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }
        ctx->digest[0] ^= A;
        ctx->digest[1] ^= B;
        ctx->digest[2] ^= C;
        ctx->digest[3] ^= D;
        ctx->digest[4] ^= E;
        ctx->digest[5] ^= F;
        ctx->digest[6] ^= G;
        ctx->digest[7] ^= H;
    }
    return i;
}

void sm3_update(sm3_context_t* ctx, const unsigned char* data,
                unsigned long len) {
    unsigned long i = 0;
    unsigned long n = 0;
    ctx->length += len;
    // solve unhandle first.
    if (ctx->unhandle_len) {
        for (i = 0; i < len && i + ctx->unhandle_len < 64; i++) {
            ctx->unhandle[ctx->unhandle_len + i] = data[i];
        }
        if (ctx->unhandle_len + i == 64) {
            sm3_update_block(ctx, ctx->unhandle, 64);
            ctx->unhandle_len = 0;
        } else {
            ctx->unhandle_len = ctx->unhandle_len + i;
            return;
        }
    }
    // then solve the data of others
    if (len - i >= 64) {
        n = sm3_update_block(ctx, data + i, len - i);
    }
    // save the reset of data into unhandle.
    for (i = i + n; i < len; i++) {
        ctx->unhandle[ctx->unhandle_len++] = data[i];
    }
}

static const unsigned char sm3_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void sm3_finish(sm3_context_t* ctx, unsigned char sum[32]) {
    // pad
    unsigned long pad;
    unsigned long long length = ctx->length * 8;

    if (ctx->unhandle_len < 56) {
        pad = 56 - ctx->unhandle_len;
    } else {
        pad = 120 - ctx->unhandle_len;
    }
    sm3_update(ctx, sm3_padding, pad);

    // append message length
    ctx->unhandle[ctx->unhandle_len++] = (length >> 56) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length >> 48) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length >> 40) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length >> 32) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length >> 24) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length >> 16) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length >> 8) & 0xff;
    ctx->unhandle[ctx->unhandle_len++] = (length)&0xff;
    sm3_update_block(ctx, ctx->unhandle, 64UL);
    PUTU32(ctx->digest[0], sum, 0);
    PUTU32(ctx->digest[1], sum, 4);
    PUTU32(ctx->digest[2], sum, 8);
    PUTU32(ctx->digest[3], sum, 12);
    PUTU32(ctx->digest[4], sum, 16);
    PUTU32(ctx->digest[5], sum, 20);
    PUTU32(ctx->digest[6], sum, 24);
    PUTU32(ctx->digest[7], sum, 28);
}

void sm3(const unsigned char* data, unsigned long len, unsigned char sum[32]) {
    sm3_context_t ctx;

    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_finish(&ctx, sum);
}
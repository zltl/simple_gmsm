#ifndef SIMPLE_GMSM_MONTGOMERY_H_
#define SIMPLE_GMSM_MONTGOMERY_H_

#ifndef USE_SLOW_BIGINT

#include <string.h>

#include "simple_gmsm/big.h"

typedef struct sgmsm_mont_ctx_p {
    big_t modulus;
    big_t std_one;
    big_t one;
    big_t r2;
    int limbs;
    big_limb_t n0_inv;
} sgmsm_mont_ctx_t;

static int sgmsm_mont_trim_used(const big_limb_t* limbs, int max) {
    int i;
    for (i = max - 1; i >= 0; i--) {
        if (limbs[i] != 0) return i + 1;
    }
    return 0;
}

static void sgmsm_mont_zero(big_t* a) {
    a->sign = 0;
    a->used = 0;
    memset(a->limbs, 0, sizeof(a->limbs));
}

static void sgmsm_mont_set_used(big_t* a, int used) {
    a->used = (uint8_t)used;
    a->sign = (used > 0) ? 1 : 0;
}

static int sgmsm_mont_cmp_limbs(const big_limb_t* a,
                                const big_limb_t* b, int limbs) {
    int i;
    for (i = limbs - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static big_limb_t sgmsm_mont_neg_inv(big_limb_t n0) {
    big_limb_t inv = 1;
    int i;

    for (i = 0; i < 6; i++) {
        inv *= (big_limb_t)(2 - n0 * inv);
    }
    return (big_limb_t)(0 - inv);
}

static void sgmsm_mont_reduce(big_t* out, big_limb_t* t,
                              const sgmsm_mont_ctx_t* ctx) {
    int i, j;
    int limbs = ctx->limbs;
    big_limb_t high;

    for (i = 0; i < limbs; i++) {
        big_limb_t m = t[i] * ctx->n0_inv;
        big_limb_t carry = 0;

        for (j = 0; j < limbs; j++) {
            big_dlimb_t acc = (big_dlimb_t)m * ctx->modulus.limbs[j]
                            + t[i + j] + carry;
            t[i + j] = (big_limb_t)acc;
            carry = (big_limb_t)(acc >> BIG_LIMB_BITS);
        }

        j = i + limbs;
        while (carry != 0) {
            big_dlimb_t acc = (big_dlimb_t)t[j] + carry;
            t[j] = (big_limb_t)acc;
            carry = (big_limb_t)(acc >> BIG_LIMB_BITS);
            j++;
        }
    }

    memset(out->limbs, 0, sizeof(out->limbs));
    memcpy(out->limbs, t + limbs, (unsigned long)limbs * sizeof(big_limb_t));
    high = t[2 * limbs];
    if (high != 0 ||
        sgmsm_mont_cmp_limbs(out->limbs, ctx->modulus.limbs, limbs) >= 0) {
        big_limb_t borrow = 0;

        for (i = 0; i < limbs; i++) {
            big_dlimb_t diff = (big_dlimb_t)out->limbs[i]
                             - ctx->modulus.limbs[i] - borrow;
            out->limbs[i] = (big_limb_t)diff;
            borrow = (big_limb_t)((diff >> BIG_LIMB_BITS) != 0);
        }
    }

    sgmsm_mont_set_used(out, sgmsm_mont_trim_used(out->limbs, limbs));
    if (out->used < BIG_LIMBS) {
        memset(out->limbs + out->used, 0,
               (unsigned long)(BIG_LIMBS - out->used) * sizeof(big_limb_t));
    }
}

static void sgmsm_mont_mul(big_t* out, const big_t* a, const big_t* b,
                           const sgmsm_mont_ctx_t* ctx) {
    big_limb_t t[2 * BIG_LIMBS + 2];
    int i, j;
    int limbs = ctx->limbs;

    memset(t, 0, sizeof(t));
    for (i = 0; i < limbs; i++) {
        big_limb_t carry = 0;
        for (j = 0; j < limbs; j++) {
            big_dlimb_t acc = (big_dlimb_t)a->limbs[i] * b->limbs[j]
                            + t[i + j] + carry;
            t[i + j] = (big_limb_t)acc;
            carry = (big_limb_t)(acc >> BIG_LIMB_BITS);
        }

        j = i + limbs;
        while (carry != 0) {
            big_dlimb_t acc = (big_dlimb_t)t[j] + carry;
            t[j] = (big_limb_t)acc;
            carry = (big_limb_t)(acc >> BIG_LIMB_BITS);
            j++;
        }
    }

    sgmsm_mont_reduce(out, t, ctx);
}

static void sgmsm_mont_sqr(big_t* out, const big_t* a,
                           const sgmsm_mont_ctx_t* ctx) {
    sgmsm_mont_mul(out, a, a, ctx);
}

static void sgmsm_mont_from_std(big_t* out, const big_t* a,
                                const sgmsm_mont_ctx_t* ctx) {
    sgmsm_mont_mul(out, a, &ctx->r2, ctx);
}

static void sgmsm_mont_to_std(big_t* out, const big_t* a,
                              const sgmsm_mont_ctx_t* ctx) {
    sgmsm_mont_mul(out, a, &ctx->std_one, ctx);
}

static void sgmsm_mont_inv(big_t* out, const big_t* a,
                           const sgmsm_mont_ctx_t* ctx) {
    big_t std_a, std_inv;

    big_init(&std_a);
    big_init(&std_inv);

    sgmsm_mont_to_std(&std_a, a, ctx);
    big_inv(&std_inv, &std_a, &ctx->modulus);
    sgmsm_mont_from_std(out, &std_inv, ctx);

    big_destroy(&std_a);
    big_destroy(&std_inv);
}

static void sgmsm_mont_init(sgmsm_mont_ctx_t* ctx, const big_t* modulus) {
    big_t r;
    big_t r2;

    big_init(&ctx->modulus);
    big_init(&ctx->std_one);
    big_init(&ctx->one);
    big_init(&ctx->r2);
    big_set(&ctx->modulus, modulus);
    big_set(&ctx->std_one, &big_one);
    ctx->limbs = modulus->used;
    ctx->n0_inv = sgmsm_mont_neg_inv(modulus->limbs[0]);

    big_init(&r);
    big_init(&r2);
    sgmsm_mont_zero(&r);
    sgmsm_mont_zero(&r2);

    r.limbs[ctx->limbs] = 1;
    sgmsm_mont_set_used(&r, ctx->limbs + 1);
    big_mod(&ctx->one, &r, modulus);

    r2.limbs[ctx->limbs * 2] = 1;
    sgmsm_mont_set_used(&r2, ctx->limbs * 2 + 1);
    big_mod(&ctx->r2, &r2, modulus);

    big_destroy(&r);
    big_destroy(&r2);
}

static void sgmsm_mont_destroy(sgmsm_mont_ctx_t* ctx) {
    big_destroy(&ctx->modulus);
    big_destroy(&ctx->std_one);
    big_destroy(&ctx->one);
    big_destroy(&ctx->r2);
    ctx->limbs = 0;
    ctx->n0_inv = 0;
}

#endif

#endif
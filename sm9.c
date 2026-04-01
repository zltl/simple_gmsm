#include "simple_gmsm/sm9.h"

#include <stdlib.h>
#include <string.h>

#include "endian.h"
#include "simple_gmsm/sm3.h"
#include "simple_gmsm/sm4.h"

/* Constant-time memory comparison (prevents timing side-channels) */
static int ct_memcmp(const unsigned char* a, const unsigned char* b,
                     unsigned long len) {
    unsigned char diff = 0;
    for (unsigned long i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return (diff == 0) ? 0 : 1;
}

/* Secure wipe: volatile pointer prevents compiler from optimizing away */
static void secure_wipe(void* p, unsigned long len) {
    volatile unsigned char* vp = (volatile unsigned char*)p;
    for (unsigned long i = 0; i < len; i++)
        vp[i] = 0;
}

/* ── SM9 BN256 curve parameters ───────────────────────────────────── */

big_t sm9_p;
big_t sm9_n;
big_t sm9_b;
sm9_g1_t sm9_P1;
sm9_g2_t sm9_P2;

static big_t sm9_one;
static big_t sm9_zero;
static big_t sm9_two;

/* Raw parameter bytes */
static unsigned char _sm9_p[] = {
    0xB6,0x40,0x00,0x00,0x02,0xA3,0xA6,0xF1,
    0xD6,0x03,0xAB,0x4F,0xF5,0x8E,0xC7,0x45,
    0x21,0xF2,0x93,0x4B,0x1A,0x7A,0xEE,0xDB,
    0xE5,0x6F,0x9B,0x27,0xE3,0x51,0x45,0x7D
};
static unsigned char _sm9_n[] = {
    0xB6,0x40,0x00,0x00,0x02,0xA3,0xA6,0xF1,
    0xD6,0x03,0xAB,0x4F,0xF5,0x8E,0xC7,0x44,
    0x49,0xF2,0x93,0x4B,0x18,0xEA,0x8B,0xEE,
    0xE5,0x6E,0xE1,0x9C,0xD6,0x9E,0xCF,0x25
};
static unsigned char _sm9_b_val[] = { 0x05 };

/* G1 generator */
static unsigned char _sm9_g1x[] = {
    0x93,0xDE,0x05,0x1D,0x62,0xBF,0x71,0x8F,
    0xF5,0xED,0x07,0x04,0x48,0x7D,0x01,0xD6,
    0xE1,0xE4,0x08,0x69,0x09,0xDC,0x32,0x80,
    0xE8,0xC4,0xE4,0x81,0x7C,0x66,0xDD,0xDD
};
static unsigned char _sm9_g1y[] = {
    0x21,0xFE,0x8D,0xDA,0x4F,0x21,0xE6,0x07,
    0x63,0x10,0x65,0x12,0x5C,0x39,0x5B,0xBC,
    0x1C,0x1C,0x00,0xCB,0xFA,0x60,0x24,0x35,
    0x0C,0x46,0x4C,0xD7,0x0A,0x3E,0xA6,0x16
};

/* G2 generator (Fp2 components) */
static unsigned char _sm9_g2x0[] = {
    0x85,0xAE,0xF3,0xD0,0x78,0x64,0x0C,0x98,
    0x59,0x7B,0x60,0x27,0xB4,0x41,0xA0,0x1F,
    0xF1,0xDD,0x2C,0x19,0x0F,0x5E,0x93,0xC4,
    0x54,0x80,0x6C,0x11,0xD8,0x80,0x61,0x41
};
static unsigned char _sm9_g2x1[] = {
    0x37,0x22,0x75,0x52,0x92,0x13,0x0B,0x08,
    0xD2,0xAA,0xB9,0x7F,0xD3,0x4E,0xC1,0x20,
    0xEE,0x26,0x59,0x48,0xD1,0x9C,0x17,0xAB,
    0xF9,0xB7,0x21,0x3B,0xAF,0x82,0xD6,0x5B
};
static unsigned char _sm9_g2y0[] = {
    0x17,0x50,0x9B,0x09,0x2E,0x84,0x5C,0x12,
    0x66,0xBA,0x0D,0x26,0x2C,0xBE,0xE6,0xED,
    0x07,0x36,0xA9,0x6F,0xA3,0x47,0xC8,0xBD,
    0x85,0x6D,0xC7,0x6B,0x84,0xEB,0xEB,0x96
};
static unsigned char _sm9_g2y1[] = {
    0xA7,0xCF,0x28,0xD5,0x19,0xBE,0x3D,0xA6,
    0x5F,0x31,0x70,0x15,0x3D,0x27,0x8F,0xF2,
    0x47,0xEF,0xBA,0x98,0xA7,0x1A,0x08,0x11,
    0x62,0x15,0xBB,0xA5,0xC9,0x99,0xA7,0xC7
};

/* R-ate pairing loop: signed-digit representation of 6u+2 (MSB first,
   '0'=0, '1'=+1, '2'=-1).  Initial T=Q provides the implicit leading 1. */
static const char _sm9_ate_naf[] =
    "00100000000000000000000000000000000000010000101100020200101000020";

/* Frobenius constants for twist point (affine coordinates):
   pi(x',y') = (conj(x')*alpha_x, conj(y')*alpha_y)
   -pi^2(x',y') = (x'*beta_x, y')  [y unchanged since beta_y = -1] */
static const unsigned char _sm9_frob_p_x[] = {  /* beta^((-p+1)/3) */
    0xb6,0x40,0x00,0x00,0x02,0xa3,0xa6,0xf0,
    0xe3,0x03,0xab,0x4f,0xf2,0xeb,0x20,0x52,
    0xa9,0xf0,0x21,0x15,0xca,0xef,0x75,0xe7,
    0x0f,0x73,0x89,0x91,0x67,0x6a,0xf2,0x4a
};
static const unsigned char _sm9_frob_p_y[] = {  /* beta^((-p+1)/2) */
    0x49,0xdb,0x72,0x1a,0x26,0x99,0x67,0xc4,
    0xe0,0xa8,0xde,0xbc,0x07,0x83,0x18,0x2f,
    0x82,0x55,0x52,0x33,0x13,0x9e,0x9d,0x63,
    0xef,0xbd,0x7b,0x54,0x09,0x2c,0x75,0x6c
};
static const unsigned char _sm9_frob_p2_x[] = { /* beta^((-p^2+1)/3) */
    0xb6,0x40,0x00,0x00,0x02,0xa3,0xa6,0xf0,
    0xe3,0x03,0xab,0x4f,0xf2,0xeb,0x20,0x52,
    0xa9,0xf0,0x21,0x15,0xca,0xef,0x75,0xe7,
    0x0f,0x73,0x89,0x91,0x67,0x6a,0xf2,0x49
};

/* Precomputed final exponentiation hard part: (p^4 - p^2 + 1) / N
   767 bits = 96 bytes, for the BN256-SM9 curve */
static const unsigned char _sm9_final_exp_hard[] = {
    0x5C,0x5E,0x45,0x24,0x04,0x03,0x4E,0x2A,0xF1,0x2F,0xCA,0xD3,
    0xB3,0x1F,0xE2,0xB0,0xD6,0x2C,0xD8,0xFB,0x7B,0x49,0x7A,0x0A,
    0xDC,0x53,0xE5,0x86,0x93,0x08,0x46,0xF1,0xBA,0x4C,0xAD,0xE0,
    0x90,0x29,0xE4,0x71,0x7C,0x0C,0xA0,0x2D,0x9B,0x0D,0x86,0x49,
    0xA5,0x78,0x2C,0x82,0xFD,0xB6,0xB0,0xA1,0x0D,0xA3,0xD7,0x1B,
    0xCD,0xB1,0x3F,0xE5,0xE0,0xD4,0x9D,0xE3,0xAA,0x8A,0x47,0x48,
    0x83,0x68,0x7E,0xE0,0xC6,0xD9,0x18,0x8C,0x44,0xBF,0x9D,0x0F,
    0xA7,0x4D,0xDF,0xB7,0xA9,0xB2,0xAD,0xA5,0x93,0x15,0x28,0x55
};
static const unsigned long _sm9_final_exp_hard_len = 96;

/* ── Fp modular arithmetic helpers ────────────────────────────────── */

/* General modular exponentiation: c = base^exp mod mod */
static void mod_pow(big_t* c, const big_t* base, const big_t* exp, const big_t* mod) {
    unsigned char buf[70];
    unsigned long len = sizeof(buf);
    unsigned long i;
    int j;
    big_t result, b, tmp;

    big_to_bytes(buf, &len, exp);
    big_init(&result); big_init(&b); big_init(&tmp);
    big_set(&result, &sm9_one);
    big_set(&b, base);

    for (i = 0; i < len; i++) {
        for (j = 7; j >= 0; j--) {
            big_mul(&tmp, &result, &result);
            big_mod(&result, &tmp, mod);
            if ((buf[i] >> j) & 1) {
                big_mul(&tmp, &result, &b);
                big_mod(&result, &tmp, mod);
            }
        }
    }
    big_set(c, &result);
    big_destroy(&result); big_destroy(&b); big_destroy(&tmp);
}

/* Modular inverse via Fermat: a^(-1) = a^(m-2) mod m */
static void mod_inv(big_t* c, const big_t* a, const big_t* m) {
    big_t exp;
    big_init(&exp);
    big_sub(&exp, m, &sm9_two);
    mod_pow(c, a, &exp, m);
    big_destroy(&exp);
}

static void fp_add(big_t* c, const big_t* a, const big_t* b) {
    big_add(c, a, b);
    if (big_cmp(c, &sm9_p) >= 0) {
        big_t tmp;
        big_init(&tmp);
        big_sub(&tmp, c, &sm9_p);
        big_set(c, &tmp);
        big_destroy(&tmp);
    }
}

static void fp_sub(big_t* c, const big_t* a, const big_t* b) {
    big_sub(c, a, b);
    if (big_cmp(c, &sm9_zero) < 0) {
        big_t tmp;
        big_init(&tmp);
        big_add(&tmp, c, &sm9_p);
        big_set(c, &tmp);
        big_destroy(&tmp);
    }
}

static void fp_mul(big_t* c, const big_t* a, const big_t* b) {
    big_t tmp;
    big_init(&tmp);
    big_mul(&tmp, a, b);
    big_mod(c, &tmp, &sm9_p);
    big_destroy(&tmp);
}

static void fp_sqr(big_t* c, const big_t* a) {
    fp_mul(c, a, a);
}

static void fp_neg(big_t* c, const big_t* a) {
    if (big_cmp(a, &sm9_zero) == 0) {
        big_set(c, &sm9_zero);
    } else {
        big_sub(c, &sm9_p, a);
    }
}

/* Fermat's little theorem: a^(-1) = a^(p-2) mod p */
static void fp_inv(big_t* c, const big_t* a) {
    mod_inv(c, a, &sm9_p);
}

/* ── Fp2 = Fp[u]/(u^2+2), i.e. u^2 = -2 (per GB/T 38635) ────────── */

static void fp2_set_zero(fp2_t* a) {
    big_set(&a->a0, &sm9_zero);
    big_set(&a->a1, &sm9_zero);
}

static void fp2_set(fp2_t* c, const fp2_t* a) {
    big_set(&c->a0, &a->a0);
    big_set(&c->a1, &a->a1);
}

static int fp2_is_zero(const fp2_t* a) {
    return big_cmp(&a->a0, &sm9_zero) == 0 && big_cmp(&a->a1, &sm9_zero) == 0;
}

static void fp2_add(fp2_t* c, const fp2_t* a, const fp2_t* b) {
    fp_add(&c->a0, &a->a0, &b->a0);
    fp_add(&c->a1, &a->a1, &b->a1);
}

static void fp2_sub(fp2_t* c, const fp2_t* a, const fp2_t* b) {
    fp_sub(&c->a0, &a->a0, &b->a0);
    fp_sub(&c->a1, &a->a1, &b->a1);
}

static void fp2_neg(fp2_t* c, const fp2_t* a) {
    fp_neg(&c->a0, &a->a0);
    fp_neg(&c->a1, &a->a1);
}

/* (a0+a1*u)(b0+b1*u) = (a0*b0 - 2*a1*b1) + (a0*b1 + a1*b0)*u */
static void fp2_mul(fp2_t* c, const fp2_t* a, const fp2_t* b) {
    big_t t0, t1, t2, t3;
    big_init(&t0); big_init(&t1); big_init(&t2); big_init(&t3);

    fp_mul(&t0, &a->a0, &b->a0);  /* a0*b0 */
    fp_mul(&t1, &a->a1, &b->a1);  /* a1*b1 */
    fp_mul(&t2, &a->a0, &b->a1);  /* a0*b1 */
    fp_mul(&t3, &a->a1, &b->a0);  /* a1*b0 */

    fp_add(&t1, &t1, &t1);        /* 2*a1*b1 */
    fp_sub(&c->a0, &t0, &t1);     /* a0*b0 - 2*a1*b1 */
    fp_add(&c->a1, &t2, &t3);     /* a0*b1 + a1*b0 */

    big_destroy(&t0); big_destroy(&t1);
    big_destroy(&t2); big_destroy(&t3);
}

static void fp2_sqr(fp2_t* c, const fp2_t* a) {
    fp2_mul(c, a, a);
}

/* conjugate: (a0+a1*u)* = a0-a1*u */
static void fp2_conj(fp2_t* c, const fp2_t* a) {
    big_set(&c->a0, &a->a0);
    fp_neg(&c->a1, &a->a1);
}

/* multiply by u: (a0+a1*u)*u = -2*a1 + a0*u  since u^2=-2 */
static void fp2_mul_u(fp2_t* c, const fp2_t* a) {
    big_t tmp;
    big_init(&tmp);
    fp_add(&tmp, &a->a1, &a->a1);  /* 2*a1 */
    fp_neg(&tmp, &tmp);             /* -2*a1 */
    big_set(&c->a1, &a->a0);
    big_set(&c->a0, &tmp);
    big_destroy(&tmp);
}

static void fp2_inv(fp2_t* c, const fp2_t* a) {
    /* 1/(a0+a1*u) = (a0-a1*u)/(a0^2+2*a1^2) with u^2=-2 */
    big_t t0, t1, inv_d;
    big_init(&t0); big_init(&t1); big_init(&inv_d);

    fp_sqr(&t0, &a->a0);
    fp_sqr(&t1, &a->a1);
    fp_add(&t1, &t1, &t1);        /* 2*a1^2 */
    fp_add(&t0, &t0, &t1);        /* a0^2 + 2*a1^2 */
    fp_inv(&inv_d, &t0);

    fp_mul(&c->a0, &a->a0, &inv_d);
    fp_neg(&t0, &a->a1);
    fp_mul(&c->a1, &t0, &inv_d);

    big_destroy(&t0); big_destroy(&t1); big_destroy(&inv_d);
}

/* multiply fp2 by scalar in Fp */
static void fp2_mul_fp(fp2_t* c, const fp2_t* a, const big_t* s) {
    fp_mul(&c->a0, &a->a0, s);
    fp_mul(&c->a1, &a->a1, s);
}

/* ── Fp4 = Fp2[v]/(v^2-u) ────────────────────────────────────────── */

static void fp4_set_zero(fp4_t* a) {
    fp2_set_zero(&a->a0);
    fp2_set_zero(&a->a1);
}

static void fp4_set(fp4_t* c, const fp4_t* a) {
    fp2_set(&c->a0, &a->a0);
    fp2_set(&c->a1, &a->a1);
}

static int __attribute__((unused)) fp4_is_zero(const fp4_t* a) {
    return fp2_is_zero(&a->a0) && fp2_is_zero(&a->a1);
}

static void fp4_add(fp4_t* c, const fp4_t* a, const fp4_t* b) {
    fp2_add(&c->a0, &a->a0, &b->a0);
    fp2_add(&c->a1, &a->a1, &b->a1);
}

static void fp4_sub(fp4_t* c, const fp4_t* a, const fp4_t* b) {
    fp2_sub(&c->a0, &a->a0, &b->a0);
    fp2_sub(&c->a1, &a->a1, &b->a1);
}

static void __attribute__((unused)) fp4_neg(fp4_t* c, const fp4_t* a) {
    fp2_neg(&c->a0, &a->a0);
    fp2_neg(&c->a1, &a->a1);
}

/* (a0+a1*v)(b0+b1*v) = (a0*b0 + a1*b1*u) + (a0*b1 + a1*b0)*v
   since v^2 = u */
static void fp4_mul(fp4_t* c, const fp4_t* a, const fp4_t* b) {
    fp2_t t0, t1, t2, t3;
    fp4_t res;
    memset(&t0, 0, sizeof(t0)); memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2)); memset(&t3, 0, sizeof(t3));
    memset(&res, 0, sizeof(res));

    fp2_mul(&t0, &a->a0, &b->a0);  /* a0*b0 */
    fp2_mul(&t1, &a->a1, &b->a1);  /* a1*b1 */
    fp2_mul_u(&t2, &t1);            /* a1*b1*u */
    fp2_add(&res.a0, &t0, &t2);    /* a0*b0 + a1*b1*u */

    fp2_mul(&t2, &a->a0, &b->a1);  /* a0*b1 */
    fp2_mul(&t3, &a->a1, &b->a0);  /* a1*b0 */
    fp2_add(&res.a1, &t2, &t3);    /* a0*b1 + a1*b0 */
    fp4_set(c, &res);
}

static void fp4_sqr(fp4_t* c, const fp4_t* a) {
    fp4_mul(c, a, a);
}

static void fp4_inv(fp4_t* c, const fp4_t* a) {
    /* 1/(a0+a1*v) = (a0-a1*v)/(a0^2 - a1^2*u) */
    fp2_t t0, t1, t2, inv_d;
    memset(&t0, 0, sizeof(t0)); memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2)); memset(&inv_d, 0, sizeof(inv_d));

    fp2_sqr(&t0, &a->a0);          /* a0^2 */
    fp2_sqr(&t1, &a->a1);
    fp2_mul_u(&t2, &t1);           /* a1^2 * u */
    fp2_sub(&t0, &t0, &t2);       /* a0^2 - a1^2*u */
    fp2_inv(&inv_d, &t0);

    fp2_mul(&c->a0, &a->a0, &inv_d);
    fp2_neg(&t0, &a->a1);
    fp2_mul(&c->a1, &t0, &inv_d);
}

/* multiply by v: (a0+a1*v)*v = a1*u + a0*v  since v^2=u */
static void fp4_mul_v(fp4_t* c, const fp4_t* a) {
    fp2_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    fp2_mul_u(&tmp, &a->a1);  /* a1 * u */
    fp2_set(&c->a1, &a->a0);
    fp2_set(&c->a0, &tmp);
}

/* ── Fp12 = Fp4[w]/(w^3-v) ───────────────────────────────────────── */

static void __attribute__((unused)) fp12_set_zero(fp12_t* a) {
    fp4_set_zero(&a->a0);
    fp4_set_zero(&a->a1);
    fp4_set_zero(&a->a2);
}

static void fp12_set_one(fp12_t* a) {
    fp4_set_zero(&a->a0);
    fp4_set_zero(&a->a1);
    fp4_set_zero(&a->a2);
    big_set(&a->a0.a0.a0, &sm9_one);
}

static void fp12_set(fp12_t* c, const fp12_t* a) {
    fp4_set(&c->a0, &a->a0);
    fp4_set(&c->a1, &a->a1);
    fp4_set(&c->a2, &a->a2);
}

/* (a0+a1*w+a2*w^2)(b0+b1*w+b2*w^2) mod (w^3-v) */
static void fp12_mul(fp12_t* c, const fp12_t* a, const fp12_t* b) {
    fp4_t t0, t1, t2, t3, t4, t5;
    fp12_t res;
    memset(&t0, 0, sizeof(t0)); memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2)); memset(&t3, 0, sizeof(t3));
    memset(&t4, 0, sizeof(t4)); memset(&t5, 0, sizeof(t5));
    memset(&res, 0, sizeof(res));

    fp4_mul(&t0, &a->a0, &b->a0);  /* a0*b0 */
    fp4_mul(&t1, &a->a1, &b->a1);  /* a1*b1 */
    fp4_mul(&t2, &a->a2, &b->a2);  /* a2*b2 */

    /* c0 = a0*b0 + (a1*b2 + a2*b1)*v */
    fp4_mul(&t3, &a->a1, &b->a2);
    fp4_mul(&t4, &a->a2, &b->a1);
    fp4_add(&t3, &t3, &t4);
    fp4_mul_v(&t3, &t3);
    fp4_add(&res.a0, &t0, &t3);

    /* c1 = a0*b1 + a1*b0 + a2*b2*v */
    fp4_mul(&t3, &a->a0, &b->a1);
    fp4_mul(&t4, &a->a1, &b->a0);
    fp4_add(&t3, &t3, &t4);
    fp4_mul_v(&t5, &t2);
    fp4_add(&res.a1, &t3, &t5);

    /* c2 = a0*b2 + a1*b1 + a2*b0 */
    fp4_mul(&t3, &a->a0, &b->a2);
    fp4_mul(&t4, &a->a2, &b->a0);
    fp4_add(&t3, &t3, &t4);
    fp4_add(&res.a2, &t3, &t1);
    fp12_set(c, &res);
}

static void fp12_sqr(fp12_t* c, const fp12_t* a) {
    fp12_mul(c, a, a);
}

static void fp12_inv(fp12_t* c, const fp12_t* a) {
    /* Using the formula for inverse in cubic extension */
    fp4_t t0, t1, t2, t3, t4, t5, det;
    memset(&t0, 0, sizeof(t0)); memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2)); memset(&t3, 0, sizeof(t3));
    memset(&t4, 0, sizeof(t4)); memset(&t5, 0, sizeof(t5));
    memset(&det, 0, sizeof(det));

    /* A = a0^2 - a1*a2*v */
    fp4_sqr(&t0, &a->a0);
    fp4_mul(&t1, &a->a1, &a->a2);
    fp4_mul_v(&t1, &t1);
    fp4_sub(&t3, &t0, &t1);  /* A = t3 */

    /* B = a2^2*v - a0*a1 */
    fp4_sqr(&t0, &a->a2);
    fp4_mul_v(&t0, &t0);
    fp4_mul(&t1, &a->a0, &a->a1);
    fp4_sub(&t4, &t0, &t1);  /* B = t4 */

    /* C = a1^2 - a0*a2 */
    fp4_sqr(&t0, &a->a1);
    fp4_mul(&t1, &a->a0, &a->a2);
    fp4_sub(&t5, &t0, &t1);  /* C = t5 */

    /* det = a0*A + a2*B*v + a1*C*v */
    fp4_mul(&t0, &a->a0, &t3);
    fp4_mul(&t1, &a->a2, &t4);
    fp4_mul_v(&t1, &t1);
    fp4_add(&det, &t0, &t1);
    fp4_mul(&t1, &a->a1, &t5);
    fp4_mul_v(&t1, &t1);
    fp4_add(&det, &det, &t1);

    fp4_inv(&det, &det);

    fp4_mul(&c->a0, &t3, &det);
    fp4_mul(&c->a1, &t4, &det);
    fp4_mul(&c->a2, &t5, &det);
}

/* Frobenius: raise to power p */
/* For BN curves, Frobenius has special structure using precomputed constants */
/* Simplified: we use fp12_pow for now */
static void fp12_pow(fp12_t* c, const fp12_t* a, const big_t* exp) {
    unsigned char buf[70];
    unsigned long len = sizeof(buf);
    unsigned long i;
    int j;
    fp12_t result, base;

    big_to_bytes(buf, &len, exp);

    fp12_set_one(&result);
    fp12_set(&base, a);

    for (i = 0; i < len; i++) {
        for (j = 7; j >= 0; j--) {
            fp12_sqr(&result, &result);
            if ((buf[i] >> j) & 1) {
                fp12_mul(&result, &result, &base);
            }
        }
    }
    fp12_set(c, &result);
}

/* Exponentiation with raw byte-array exponent (for values exceeding big_t) */
static void fp12_pow_bytes(fp12_t* c, const fp12_t* a,
                           const unsigned char* exp, unsigned long explen) {
    unsigned long i;
    int j;
    fp12_t result, base;

    fp12_set_one(&result);
    fp12_set(&base, a);

    for (i = 0; i < explen; i++) {
        for (j = 7; j >= 0; j--) {
            fp12_sqr(&result, &result);
            if ((exp[i] >> j) & 1) {
                fp12_mul(&result, &result, &base);
            }
        }
    }
    fp12_set(c, &result);
}

/* ── Fp12 Frobenius maps ──────────────────────────────────────────── */

/* Precomputed Frobenius constants for the tower
   Fp2=Fp[u]/(u²+2), Fp4=Fp2[v]/(v²-u), Fp12=Fp4[w]/(w³-v)
   w^(p-1) = delta = (-2)^((p-1)/12) */
static big_t _frob_delta;   /* w^(p-1) for p-Frobenius */
static big_t _frob_delta_sq; /* delta^2 */
static big_t _frob_gamma;   /* v^(p-1) = delta^3 for p-Frobenius on Fp4 */
static big_t _frob_delta2;  /* w^(p²-1) for p²-Frobenius */
static big_t _frob_delta2_sq; /* delta2^2 */

static const unsigned char _frob_delta_bytes[] = {
    0x3f,0x23,0xea,0x58,0xe5,0x72,0x0b,0xdb,
    0x84,0x3c,0x6c,0xfa,0x9c,0x08,0x67,0x49,
    0x47,0xc5,0xc8,0x6e,0x0d,0xdd,0x04,0xed,
    0xa9,0x1d,0x83,0x54,0x37,0x7b,0x69,0x8b
};
static const unsigned char _frob_delta_sq_bytes[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xf3,0x00,0x00,0x00,0x02,0xa3,0xa6,0xf2,
    0x78,0x02,0x72,0x35,0x4f,0x8b,0x78,0xf4,
    0xd5,0xfc,0x11,0x96,0x7b,0xe6,0x53,0x34
};
static const unsigned char _frob_gamma_bytes[] = {
    0x6c,0x64,0x8d,0xe5,0xdc,0x0a,0x3f,0x2c,
    0xf5,0x5a,0xcc,0x93,0xee,0x0b,0xaf,0x15,
    0x9f,0x9d,0x41,0x18,0x06,0xdc,0x51,0x77,
    0xf5,0xb2,0x1f,0xd3,0xda,0x24,0xd0,0x11
};
static const unsigned char _frob_delta2_bytes[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xf3,0x00,0x00,0x00,0x02,0xa3,0xa6,0xf2,
    0x78,0x02,0x72,0x35,0x4f,0x8b,0x78,0xf4,
    0xd5,0xfc,0x11,0x96,0x7b,0xe6,0x53,0x34
};
static const unsigned char _frob_delta2_sq_bytes[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xf3,0x00,0x00,0x00,0x02,0xa3,0xa6,0xf2,
    0x78,0x02,0x72,0x35,0x4f,0x8b,0x78,0xf4,
    0xd5,0xfc,0x11,0x96,0x7b,0xe6,0x53,0x33
};

static int _frob_inited = 0;
static void frob_const_init(void) {
    if (_frob_inited) return;
    big_init(&_frob_delta); big_init(&_frob_delta_sq);
    big_init(&_frob_gamma);
    big_init(&_frob_delta2); big_init(&_frob_delta2_sq);
    big_from_bytes(&_frob_delta, (unsigned char*)_frob_delta_bytes, 32);
    big_from_bytes(&_frob_delta_sq, (unsigned char*)_frob_delta_sq_bytes, 32);
    big_from_bytes(&_frob_gamma, (unsigned char*)_frob_gamma_bytes, 32);
    big_from_bytes(&_frob_delta2, (unsigned char*)_frob_delta2_bytes, 32);
    big_from_bytes(&_frob_delta2_sq, (unsigned char*)_frob_delta2_sq_bytes, 32);
    _frob_inited = 1;
}

/* p^6-Frobenius on Fp12:
   sigma6(a0 + a1*w + a2*w^2) where each ai = (ai.a0, ai.a1) in Fp4
   delta6 = -1, gamma6 = -1, sigma6 on Fp2 = identity
   Result: (a0.a0, -a0.a1) + (-a1.a0, a1.a1)*w + (a2.a0, -a2.a1)*w^2 */
static void fp12_frobenius_p6(fp12_t* c, const fp12_t* a) {
    /* a0: negate v-coefficient */
    fp2_set(&c->a0.a0, &a->a0.a0);
    fp2_neg(&c->a0.a1, &a->a0.a1);
    /* a1: negate constant, keep v-coefficient */
    fp2_neg(&c->a1.a0, &a->a1.a0);
    fp2_set(&c->a1.a1, &a->a1.a1);
    /* a2: negate v-coefficient */
    fp2_set(&c->a2.a0, &a->a2.a0);
    fp2_neg(&c->a2.a1, &a->a2.a1);
}

/* p^2-Frobenius on Fp12:
   sigma2 on Fp2 = identity
   sigma2 on Fp4: (b0, b1) -> (b0, -b1) since gamma2 = -1
   sigma2 on Fp12: (a0', a1'*delta2, a2'*delta2^2) where ai' = sigma2_fp4(ai) */
static void fp12_frobenius_p2(fp12_t* c, const fp12_t* a) {
    frob_const_init();
    /* a0: sigma2_fp4 = (a0.a0, -a0.a1) */
    fp2_set(&c->a0.a0, &a->a0.a0);
    fp2_neg(&c->a0.a1, &a->a0.a1);
    /* a1: sigma2_fp4(a1) * delta2 */
    fp2_mul_fp(&c->a1.a0, &a->a1.a0, &_frob_delta2);
    {
        fp2_t neg_a1_1;
        fp2_neg(&neg_a1_1, &a->a1.a1);
        fp2_mul_fp(&c->a1.a1, &neg_a1_1, &_frob_delta2);
    }
    /* a2: sigma2_fp4(a2) * delta2^2 */
    fp2_mul_fp(&c->a2.a0, &a->a2.a0, &_frob_delta2_sq);
    {
        fp2_t neg_a2_1;
        fp2_neg(&neg_a2_1, &a->a2.a1);
        fp2_mul_fp(&c->a2.a1, &neg_a2_1, &_frob_delta2_sq);
    }
}

/* p-Frobenius on Fp12:
   sigma on Fp2 = conjugation
   sigma on Fp4: (conj(b0), conj(b1)*gamma)
   sigma on Fp12: (sigma_fp4(a0), sigma_fp4(a1)*delta, sigma_fp4(a2)*delta^2) */
static void fp12_frobenius_p(fp12_t* c, const fp12_t* a) {
    frob_const_init();
    /* a0: sigma_fp4 = (conj(a0.a0), conj(a0.a1)*gamma) */
    fp2_conj(&c->a0.a0, &a->a0.a0);
    {
        fp2_t t;
        fp2_conj(&t, &a->a0.a1);
        fp2_mul_fp(&c->a0.a1, &t, &_frob_gamma);
    }
    /* a1: sigma_fp4(a1) * delta */
    {
        fp2_t t0, t1;
        fp2_conj(&t0, &a->a1.a0);
        fp2_mul_fp(&c->a1.a0, &t0, &_frob_delta);
        fp2_conj(&t1, &a->a1.a1);
        fp2_mul_fp(&t1, &t1, &_frob_gamma);
        fp2_mul_fp(&c->a1.a1, &t1, &_frob_delta);
    }
    /* a2: sigma_fp4(a2) * delta^2 */
    {
        fp2_t t0, t1;
        fp2_conj(&t0, &a->a2.a0);
        fp2_mul_fp(&c->a2.a0, &t0, &_frob_delta_sq);
        fp2_conj(&t1, &a->a2.a1);
        fp2_mul_fp(&t1, &t1, &_frob_gamma);
        fp2_mul_fp(&c->a2.a1, &t1, &_frob_delta_sq);
    }
}

/* p^3-Frobenius: apply p-Frobenius then p^2-Frobenius */
static void __attribute__((unused)) fp12_frobenius_p3(fp12_t* c, const fp12_t* a) {
    fp12_t tmp;
    fp12_frobenius_p(&tmp, a);
    fp12_frobenius_p2(c, &tmp);
}

/* ── G1 point operations (E(Fp): y^2 = x^3 + b) ─────────────────── */

static int g1_is_inf(const sm9_g1_t* p) {
    return big_cmp(&p->x, &sm9_zero) == 0 && big_cmp(&p->y, &sm9_zero) == 0;
}

static void g1_set_inf(sm9_g1_t* p) {
    big_set(&p->x, &sm9_zero);
    big_set(&p->y, &sm9_zero);
}

static void g1_set(sm9_g1_t* c, const sm9_g1_t* a) {
    big_set(&c->x, &a->x);
    big_set(&c->y, &a->y);
}

static int g1_on_curve(const sm9_g1_t* p) {
    big_t lhs, rhs, tmp;
    int r;
    big_init(&lhs); big_init(&rhs); big_init(&tmp);

    fp_sqr(&lhs, &p->y);        /* y^2 */
    fp_sqr(&tmp, &p->x);
    fp_mul(&rhs, &tmp, &p->x);  /* x^3 */
    fp_add(&rhs, &rhs, &sm9_b); /* x^3 + b */

    r = (big_cmp(&lhs, &rhs) == 0);
    big_destroy(&lhs); big_destroy(&rhs); big_destroy(&tmp);
    return r;
}

static void g1_add(sm9_g1_t* c, const sm9_g1_t* a, const sm9_g1_t* b) {
    big_t lam, t1, t2;
    sm9_g1_t res;

    if (g1_is_inf(a)) { g1_set(c, b); return; }
    if (g1_is_inf(b)) { g1_set(c, a); return; }

    big_init(&lam); big_init(&t1); big_init(&t2);

    if (big_cmp(&a->x, &b->x) == 0) {
        if (big_cmp(&a->y, &b->y) == 0) {
            /* double */
            big_t three;
            big_init(&three);
            big_set(&three, &sm9_zero);
            fp_add(&three, &sm9_one, &sm9_two);

            fp_sqr(&t1, &a->x);
            fp_mul(&t1, &t1, &three); /* 3x^2 */
            /* + a = 0 for SM9 BN curve */
            fp_add(&t2, &a->y, &a->y); /* 2y */
            fp_inv(&t2, &t2);
            fp_mul(&lam, &t1, &t2);

            fp_sqr(&t1, &lam);
            fp_sub(&t1, &t1, &a->x);
            fp_sub(&res.x, &t1, &a->x);  /* x3 = lam^2 - 2x */
            fp_sub(&t1, &a->x, &res.x);
            fp_mul(&t2, &lam, &t1);
            fp_sub(&res.y, &t2, &a->y);

            big_destroy(&three);
        } else {
            g1_set_inf(&res);
        }
    } else {
        fp_sub(&t1, &b->y, &a->y);
        fp_sub(&t2, &b->x, &a->x);
        fp_inv(&t2, &t2);
        fp_mul(&lam, &t1, &t2);

        fp_sqr(&t1, &lam);
        fp_sub(&t1, &t1, &a->x);
        fp_sub(&res.x, &t1, &b->x);
        fp_sub(&t1, &a->x, &res.x);
        fp_mul(&t2, &lam, &t1);
        fp_sub(&res.y, &t2, &a->y);
    }

    g1_set(c, &res);
    big_destroy(&lam); big_destroy(&t1); big_destroy(&t2);
}

static void g1_scalar_mult(sm9_g1_t* c, const sm9_g1_t* p, const big_t* k) {
    unsigned char buf[70];
    unsigned long len = sizeof(buf);
    unsigned long i;
    int j;
    sm9_g1_t result;

    big_to_bytes(buf, &len, k);
    g1_set_inf(&result);

    for (i = 0; i < len; i++) {
        for (j = 7; j >= 0; j--) {
            g1_add(&result, &result, &result);
            if ((buf[i] >> j) & 1) {
                g1_add(&result, &result, p);
            }
        }
    }
    g1_set(c, &result);
}

static void __attribute__((unused)) g1_neg(sm9_g1_t* c, const sm9_g1_t* a) {
    big_set(&c->x, &a->x);
    fp_neg(&c->y, &a->y);
}

/* ── G2 point operations (E'(Fp2): y^2 = x^3 + 5u) ──────────────── */
/* twist: b' = 5u = (0, 5) in fp2_t {a0, a1} representation */

static fp2_t g2_b_twist;  /* b' = (0, 5) = 5u */

static int g2_is_inf(const sm9_g2_t* p) {
    return fp2_is_zero(&p->x) && fp2_is_zero(&p->y);
}

static void g2_set_inf(sm9_g2_t* p) {
    fp2_set_zero(&p->x);
    fp2_set_zero(&p->y);
}

static void g2_set(sm9_g2_t* c, const sm9_g2_t* a) {
    fp2_set(&c->x, &a->x);
    fp2_set(&c->y, &a->y);
}

static void g2_add(sm9_g2_t* c, const sm9_g2_t* a, const sm9_g2_t* b) {
    fp2_t lam, t1, t2;
    sm9_g2_t res;

    if (g2_is_inf(a)) { g2_set(c, b); return; }
    if (g2_is_inf(b)) { g2_set(c, a); return; }

    memset(&lam, 0, sizeof(lam));
    memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2));
    memset(&res, 0, sizeof(res));

    if (big_cmp(&a->x.a0, &b->x.a0) == 0 && big_cmp(&a->x.a1, &b->x.a1) == 0) {
        if (big_cmp(&a->y.a0, &b->y.a0) == 0 && big_cmp(&a->y.a1, &b->y.a1) == 0) {
            /* double */
            fp2_t three_fp2;
            memset(&three_fp2, 0, sizeof(three_fp2));
            big_t three;
            big_init(&three);
            fp_add(&three, &sm9_one, &sm9_two);
            big_set(&three_fp2.a0, &three);
            big_set(&three_fp2.a1, &sm9_zero);

            fp2_sqr(&t1, &a->x);
            fp2_mul(&t1, &t1, &three_fp2); /* 3x^2 (a=0) */
            fp2_add(&t2, &a->y, &a->y);    /* 2y */
            fp2_inv(&t2, &t2);
            fp2_mul(&lam, &t1, &t2);

            fp2_sqr(&t1, &lam);
            fp2_sub(&t1, &t1, &a->x);
            fp2_sub(&res.x, &t1, &a->x);
            fp2_sub(&t1, &a->x, &res.x);
            fp2_mul(&t2, &lam, &t1);
            fp2_sub(&res.y, &t2, &a->y);

            big_destroy(&three);
        } else {
            g2_set_inf(&res);
        }
    } else {
        fp2_sub(&t1, &b->y, &a->y);
        fp2_sub(&t2, &b->x, &a->x);
        fp2_inv(&t2, &t2);
        fp2_mul(&lam, &t1, &t2);

        fp2_sqr(&t1, &lam);
        fp2_sub(&t1, &t1, &a->x);
        fp2_sub(&res.x, &t1, &b->x);
        fp2_sub(&t1, &a->x, &res.x);
        fp2_mul(&t2, &lam, &t1);
        fp2_sub(&res.y, &t2, &a->y);
    }

    g2_set(c, &res);
}

static void g2_scalar_mult(sm9_g2_t* c, const sm9_g2_t* p, const big_t* k) {
    unsigned char buf[70];
    unsigned long len = sizeof(buf);
    unsigned long i;
    int j;
    sm9_g2_t result;

    big_to_bytes(buf, &len, k);
    g2_set_inf(&result);

    for (i = 0; i < len; i++) {
        for (j = 7; j >= 0; j--) {
            g2_add(&result, &result, &result);
            if ((buf[i] >> j) & 1) {
                g2_add(&result, &result, p);
            }
        }
    }
    g2_set(c, &result);
}

static void g2_neg(sm9_g2_t* c, const sm9_g2_t* a) {
    fp2_set(&c->x, &a->x);
    fp2_neg(&c->y, &a->y);
}

/* p-Frobenius on affine twist point:
   pi(x,y) = (conj(x)*alpha_x, conj(y)*alpha_y) */
static void g2_frobenius_pi1(sm9_g2_t* R, const sm9_g2_t* Q) {
    big_t alpha_x, alpha_y;
    big_init(&alpha_x);
    big_init(&alpha_y);
    big_from_bytes(&alpha_x, (unsigned char*)_sm9_frob_p_x, 32);
    big_from_bytes(&alpha_y, (unsigned char*)_sm9_frob_p_y, 32);
    fp2_conj(&R->x, &Q->x);
    fp2_conj(&R->y, &Q->y);
    fp2_mul_fp(&R->x, &R->x, &alpha_x);
    fp2_mul_fp(&R->y, &R->y, &alpha_y);
    big_destroy(&alpha_x);
    big_destroy(&alpha_y);
}

/* -p^2-Frobenius on affine twist point:
   -pi^2(x,y) = (x*beta_x, y)  since beta_y = -1 mod p */
static void g2_neg_frobenius_pi2(sm9_g2_t* R, const sm9_g2_t* Q) {
    big_t beta_x;
    big_init(&beta_x);
    big_from_bytes(&beta_x, (unsigned char*)_sm9_frob_p2_x, 32);
    fp2_mul_fp(&R->x, &Q->x, &beta_x);
    fp2_set(&R->y, &Q->y);
    big_destroy(&beta_x);
}

/* ── R-ate Pairing ────────────────────────────────────────────────── */

/* Line function evaluation for Miller loop.
   For a D-type sextic twist with psi(x',y') = (x'/w^2, y'/w^3):
   line through T evaluated at P = (xP, yP) in E(Fp):
     l = (lam*xT - yT) + (-lam*xP)*w^2 + yP*w^3
   In Fp12 = Fp4[w]/(w^3-v):
     f.a0 = ((lam*xT-yT), (yP, 0))  -- Fp4 = (w^0-const, v-coeff)
     f.a1 = (0, 0)
     f.a2 = ((-lam*xP), (0, 0))     -- w^2 coefficient */
static void line_func(fp12_t* f, sm9_g2_t* T, const sm9_g2_t* Q,
                      const sm9_g1_t* P) {
    fp2_t lam, t1, t2;

    if (g2_is_inf(T) || g2_is_inf(Q)) {
        fp12_set_one(f);
        return;
    }

    int same = (big_cmp(&T->x.a0, &Q->x.a0) == 0 &&
                big_cmp(&T->x.a1, &Q->x.a1) == 0 &&
                big_cmp(&T->y.a0, &Q->y.a0) == 0 &&
                big_cmp(&T->y.a1, &Q->y.a1) == 0);

    memset(&lam, 0, sizeof(lam));
    memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2));

    if (same) {
        /* Tangent: lam = 3*xT^2 / (2*yT)  (a=0 for twist curve) */
        big_t three;
        big_init(&three);
        fp_add(&three, &sm9_one, &sm9_two);

        fp2_sqr(&t1, &T->x);           /* xT^2 */
        fp2_mul_fp(&t1, &t1, &three);   /* 3*xT^2 */
        fp2_add(&t2, &T->y, &T->y);    /* 2*yT */
        fp2_inv(&t2, &t2);
        fp2_mul(&lam, &t1, &t2);        /* lam */

        big_destroy(&three);
    } else {
        /* Secant/vertical */
        if (big_cmp(&T->x.a0, &Q->x.a0) == 0 &&
            big_cmp(&T->x.a1, &Q->x.a1) == 0) {
            fp12_set_one(f);
            g2_set_inf(T);
            return;
        }
        /* lam = (yQ - yT) / (xQ - xT) */
        fp2_sub(&t1, &Q->y, &T->y);
        fp2_sub(&t2, &Q->x, &T->x);
        fp2_inv(&t2, &t2);
        fp2_mul(&lam, &t1, &t2);
    }

    /* Build sparse Fp12 element:
       lw[0] = lam*xT - yT  ->  f.a0.a0
       lw[2] = (yP, 0)      ->  f.a0.a1
       lw[1] = -lam*xP      ->  f.a2.a0  */
    fp2_mul(&t1, &lam, &T->x);      /* lam*xT */
    fp2_sub(&t1, &t1, &T->y);       /* lam*xT - yT -> lw[0] */

    fp2_mul_fp(&t2, &lam, &P->x);   /* lam*xP */
    fp2_neg(&t2, &t2);              /* -lam*xP -> lw[1] */

    /* f.a0 = (lw[0], (yP, 0)) */
    fp2_set(&f->a0.a0, &t1);
    big_set(&f->a0.a1.a0, &P->y);
    big_set(&f->a0.a1.a1, &sm9_zero);

    /* f.a1 = (0, 0) */
    fp4_set_zero(&f->a1);

    /* f.a2 = (lw[1], (0, 0)) */
    fp2_set(&f->a2.a0, &t2);
    fp2_set_zero(&f->a2.a1);

    /* Update T using already-computed lam (avoids redundant fp2_inv in g2_add) */
    {
        fp2_t xr, yr;
        memset(&xr, 0, sizeof(xr));
        memset(&yr, 0, sizeof(yr));
        if (same) {
            /* T = 2T: xr = lam^2 - 2*xT, yr = lam*(xT - xr) - yT */
            fp2_sqr(&xr, &lam);
            fp2_sub(&xr, &xr, &T->x);
            fp2_sub(&xr, &xr, &T->x);
            fp2_sub(&yr, &T->x, &xr);
            fp2_mul(&yr, &lam, &yr);
            fp2_sub(&yr, &yr, &T->y);
        } else {
            /* T = T+Q: xr = lam^2 - xT - xQ, yr = lam*(xT - xr) - yT */
            fp2_sqr(&xr, &lam);
            fp2_sub(&xr, &xr, &T->x);
            fp2_sub(&xr, &xr, &Q->x);
            fp2_sub(&yr, &T->x, &xr);
            fp2_mul(&yr, &lam, &yr);
            fp2_sub(&yr, &yr, &T->y);
        }
        fp2_set(&T->x, &xr);
        fp2_set(&T->y, &yr);
    }
}

/* R-ate pairing: e(P, Q) where P in G1, Q in G2 */
/* Temporarily non-static for bilinearity testing */
static void sm9_pairing(fp12_t* result, const sm9_g1_t* P, const sm9_g2_t* Q) {
    sm9_g2_t T, negQ, Q1, Q2;
    fp12_t f, line;
    unsigned long i;

    if (g1_is_inf(P) || g2_is_inf(Q)) {
        fp12_set_one(result);
        return;
    }

    g2_set(&T, Q);
    g2_neg(&negQ, Q);
    fp12_set_one(&f);

    /* Miller loop over signed-digit representation of 6u+2 */
    for (i = 0; i < sizeof(_sm9_ate_naf) - 1; i++) {
        fp12_sqr(&f, &f);
        line_func(&line, &T, &T, P);   /* double T, tangent line */
        fp12_mul(&f, &f, &line);

        if (_sm9_ate_naf[i] == '1') {
            line_func(&line, &T, Q, P); /* add Q */
            fp12_mul(&f, &f, &line);
        } else if (_sm9_ate_naf[i] == '2') {
            line_func(&line, &T, &negQ, P); /* add -Q */
            fp12_mul(&f, &f, &line);
        }
    }

    /* Frobenius corrections: Q1 = pi(Q), Q2 = -pi^2(Q) */
    g2_frobenius_pi1(&Q1, Q);
    g2_neg_frobenius_pi2(&Q2, Q);

    line_func(&line, &T, &Q1, P);
    fp12_mul(&f, &f, &line);

    line_func(&line, &T, &Q2, P);
    fp12_mul(&f, &f, &line);

    /* Final exponentiation: f^((p^12-1)/N)
       Factored: (p^6-1) * (p^2+1) * (p^4-p^2+1)/N */
    {
        fp12_t t0, f_inv;

        /* Easy part 1: f^(p^6-1) = f^(p^6) * f^(-1) */
        fp12_frobenius_p6(&t0, &f);     /* f^(p^6) via Frobenius */
        fp12_inv(&f_inv, &f);
        fp12_mul(&f, &t0, &f_inv);      /* f^(p^6-1) */

        /* Easy part 2: f^(p^2+1) */
        fp12_frobenius_p2(&t0, &f);     /* f^(p^2) via Frobenius */
        fp12_mul(&f, &t0, &f);          /* f^((p^6-1)(p^2+1)) */

        /* Hard part: f^((p^4-p^2+1)/N) */
        fp12_pow_bytes(&f, &f, _sm9_final_exp_hard, _sm9_final_exp_hard_len);
    }

    fp12_set(result, &f);
}

/* ── Hash functions for SM9 ───────────────────────────────────────── */

/* H1: hash to [1, N-1] for signing */
/* H(Z, n) = (Ha(Z) mod (n-1)) + 1 */
/* Ha = SM3(0x01 || Z) || SM3(0x02 || Z) truncated */
static void sm9_hash_to_range(big_t* h, unsigned char hashtype,
                              const unsigned char* z, unsigned long zlen) {
    sm3_context_t ctx;
    unsigned char ha[64]; /* two SM3 outputs */
    unsigned char ct;
    big_t tmp, n_minus_1;

    big_init(&tmp);
    big_init(&n_minus_1);

    /* ha = SM3(0x01||ct||Z) || SM3(0x02||ct||Z) */
    ct = 0x01;
    sm3_init(&ctx);
    sm3_update(&ctx, &hashtype, 1);
    sm3_update(&ctx, &ct, 1);
    sm3_update(&ctx, z, zlen);
    sm3_finish(&ctx, ha);

    ct = 0x02;
    sm3_init(&ctx);
    sm3_update(&ctx, &hashtype, 1);
    sm3_update(&ctx, &ct, 1);
    sm3_update(&ctx, z, zlen);
    sm3_finish(&ctx, ha + 32);

    big_from_bytes(&tmp, ha, 64);
    big_sub(&n_minus_1, &sm9_n, &sm9_one);
    big_mod(h, &tmp, &n_minus_1);
    big_add(&tmp, h, &sm9_one);
    big_set(h, &tmp);

    big_destroy(&tmp);
    big_destroy(&n_minus_1);
}

/* SM9 KDF based on SM3 */
static void sm9_kdf(unsigned char* key, unsigned long keylen,
                    const unsigned char* z, unsigned long zlen) {
    unsigned long ct = 1;
    unsigned long offset = 0;
    unsigned char ctbuf[4];
    unsigned char hash[32];
    sm3_context_t ctx;

    while (offset < keylen) {
        ctbuf[0] = (unsigned char)((ct >> 24) & 0xFF);
        ctbuf[1] = (unsigned char)((ct >> 16) & 0xFF);
        ctbuf[2] = (unsigned char)((ct >> 8) & 0xFF);
        ctbuf[3] = (unsigned char)(ct & 0xFF);

        sm3_init(&ctx);
        sm3_update(&ctx, z, zlen);
        sm3_update(&ctx, ctbuf, 4);
        sm3_finish(&ctx, hash);

        unsigned long cplen = keylen - offset;
        if (cplen > 32) cplen = 32;
        memcpy(key + offset, hash, cplen);
        offset += cplen;
        ct++;
    }
}

/* ── SM9 Lifecycle ────────────────────────────────────────────────── */

void sm9_init(void) {
    big_init(&sm9_p);
    big_init(&sm9_n);
    big_init(&sm9_b);
    big_init(&sm9_one);
    big_init(&sm9_zero);
    big_init(&sm9_two);

    big_from_bytes(&sm9_p, _sm9_p, sizeof(_sm9_p));
    big_from_bytes(&sm9_n, _sm9_n, sizeof(_sm9_n));
    big_from_bytes(&sm9_b, _sm9_b_val, sizeof(_sm9_b_val));

    /* Constants */
    unsigned char one_buf[] = {1};
    unsigned char two_buf[] = {2};
    big_from_bytes(&sm9_one, one_buf, 1);
    big_from_bytes(&sm9_two, two_buf, 1);
    big_set(&sm9_zero, &big_zero);

    /* G1 generator */
    big_init(&sm9_P1.x);
    big_init(&sm9_P1.y);
    big_from_bytes(&sm9_P1.x, _sm9_g1x, sizeof(_sm9_g1x));
    big_from_bytes(&sm9_P1.y, _sm9_g1y, sizeof(_sm9_g1y));

    /* G2 generator — standard serializes Fp2 as (imag, real) per GB/T 38635.
       Our fp2_t is a0 + a1*u, so a0=real=second, a1=imag=first. */
    memset(&sm9_P2, 0, sizeof(sm9_P2));
    big_from_bytes(&sm9_P2.x.a0, _sm9_g2x1, sizeof(_sm9_g2x1));
    big_from_bytes(&sm9_P2.x.a1, _sm9_g2x0, sizeof(_sm9_g2x0));
    big_from_bytes(&sm9_P2.y.a0, _sm9_g2y1, sizeof(_sm9_g2y1));
    big_from_bytes(&sm9_P2.y.a1, _sm9_g2y0, sizeof(_sm9_g2y0));

    /* Twist parameter: b' = 5u = (0, 5) in fp2_t representation.
       E'(Fp2): y^2 = x^3 + 5u, consistent with GB/T 38635.1. */
    memset(&g2_b_twist, 0, sizeof(g2_b_twist));
    big_set(&g2_b_twist.a0, &sm9_zero);
    big_set(&g2_b_twist.a1, &sm9_b);
}

void sm9_destroy(void) {
    big_destroy(&sm9_p);
    big_destroy(&sm9_n);
    big_destroy(&sm9_b);
    big_destroy(&sm9_one);
    big_destroy(&sm9_zero);
    big_destroy(&sm9_two);
    big_destroy(&sm9_P1.x);
    big_destroy(&sm9_P1.y);
}

/* ── Key Generation ───────────────────────────────────────────────── */

void sm9_sign_master_keygen(sm9_sign_master_key_t* mk) {
    big_t tmp;
    big_init(&tmp);

    /* ks random in [1, N-1] */
    big_rand(&mk->ks, 256);
    big_sub(&tmp, &sm9_n, &sm9_two);
    big_mod(&mk->ks, &mk->ks, &tmp);
    big_add(&tmp, &mk->ks, &sm9_one);
    big_set(&mk->ks, &tmp);

    /* Ppub_s = ks * P2 */
    g2_scalar_mult(&mk->Ppub, &sm9_P2, &mk->ks);

    big_destroy(&tmp);
}

void sm9_enc_master_keygen(sm9_enc_master_key_t* mk) {
    big_t tmp;
    big_init(&tmp);

    big_rand(&mk->ke, 256);
    big_sub(&tmp, &sm9_n, &sm9_two);
    big_mod(&mk->ke, &mk->ke, &tmp);
    big_add(&tmp, &mk->ke, &sm9_one);
    big_set(&mk->ke, &tmp);

    /* Ppub_e = ke * P1 */
    g1_scalar_mult(&mk->Ppub, &sm9_P1, &mk->ke);

    big_destroy(&tmp);
}

int sm9_sign_user_key_extract(sm9_sign_user_key_t* uk,
                              const sm9_sign_master_key_t* mk,
                              const unsigned char* id, unsigned long idlen) {
    big_t h1, t1, t2;
    unsigned char* zbuf;
    unsigned long zbuflen;

    big_init(&h1); big_init(&t1); big_init(&t2);

    /* h1 = H1(IDA || hid, N) where hid = 0x01 for signing */
    zbuflen = idlen + 1;
    zbuf = (unsigned char*)malloc(zbuflen);
    if (!zbuf) { big_destroy(&h1); big_destroy(&t1); big_destroy(&t2); return 0; }
    memcpy(zbuf, id, idlen);
    zbuf[idlen] = 0x01;  /* hid for signing */
    sm9_hash_to_range(&h1, 0x01, zbuf, zbuflen);
    free(zbuf);

    /* t1 = h1 + ks mod N (scalar arithmetic, NOT mod p) */
    big_add(&t1, &h1, &mk->ks);
    big_mod(&t1, &t1, &sm9_n);

    if (big_cmp(&t1, &sm9_zero) == 0) {
        big_destroy(&h1); big_destroy(&t1); big_destroy(&t2);
        return 0; /* need to regenerate master key */
    }

    /* t2 = ks * t1^{-1} mod N */
    mod_inv(&t2, &t1, &sm9_n);
    big_mul(&t1, &mk->ks, &t2);
    big_mod(&t2, &t1, &sm9_n);

    /* dA = t2 * P1 */
    g1_scalar_mult(uk, &sm9_P1, &t2);

    big_destroy(&h1); big_destroy(&t1); big_destroy(&t2);
    return 1;
}

int sm9_enc_user_key_extract(sm9_enc_user_key_t* uk,
                             const sm9_enc_master_key_t* mk,
                             const unsigned char* id, unsigned long idlen) {
    big_t h1, t1, t2;
    unsigned char* zbuf;
    unsigned long zbuflen;

    big_init(&h1); big_init(&t1); big_init(&t2);

    zbuflen = idlen + 1;
    zbuf = (unsigned char*)malloc(zbuflen);
    if (!zbuf) { big_destroy(&h1); big_destroy(&t1); big_destroy(&t2); return 0; }
    memcpy(zbuf, id, idlen);
    zbuf[idlen] = 0x03;  /* hid for encryption */
    sm9_hash_to_range(&h1, 0x01, zbuf, zbuflen);
    free(zbuf);

    /* t1 = h1 + ke mod N (scalar arithmetic, NOT mod p) */
    big_add(&t1, &h1, &mk->ke);
    big_mod(&t1, &t1, &sm9_n);

    if (big_cmp(&t1, &sm9_zero) == 0) {
        big_destroy(&h1); big_destroy(&t1); big_destroy(&t2);
        return 0;
    }

    mod_inv(&t2, &t1, &sm9_n);
    big_mul(&t1, &mk->ke, &t2);
    big_mod(&t2, &t1, &sm9_n);

    /* de = t2 * P2 */
    g2_scalar_mult(uk, &sm9_P2, &t2);

    big_destroy(&h1); big_destroy(&t1); big_destroy(&t2);
    return 1;
}

/* ── SM9 Sign / Verify ────────────────────────────────────────────── */

void sm9_sign(unsigned char h[32], sm9_g1_t* S,
              const unsigned char* msg, unsigned long msglen,
              const sm9_sign_user_key_t* uk,
              const sm9_g2_t* Ppub) {
    fp12_t g, w;
    big_t r, hh, l;
    unsigned char wbuf[384]; /* Fp12 serialized */
    unsigned char* zbuf;
    unsigned long zbuflen, wlen;
    unsigned long i;
    big_t tmp;

    big_init(&r); big_init(&hh); big_init(&l); big_init(&tmp);

    /* g = e(P1, Ppub_s) */
    sm9_pairing(&g, &sm9_P1, Ppub);

retry:
    /* random r in [1, N-1] */
    big_rand(&r, 256);
    big_sub(&tmp, &sm9_n, &sm9_two);
    big_mod(&r, &r, &tmp);
    big_add(&tmp, &r, &sm9_one);
    big_set(&r, &tmp);

    /* w = g^r */
    fp12_pow(&w, &g, &r);

    /* Serialize w for hashing */
    /* Simple serialization: concatenate all Fp elements */
    wlen = 0;
    {
        big_t* elems[12] = {
            &w.a0.a0.a0, &w.a0.a0.a1, &w.a0.a1.a0, &w.a0.a1.a1,
            &w.a1.a0.a0, &w.a1.a0.a1, &w.a1.a1.a0, &w.a1.a1.a1,
            &w.a2.a0.a0, &w.a2.a0.a1, &w.a2.a1.a0, &w.a2.a1.a1
        };
        for (i = 0; i < 12; i++) {
            unsigned long elen = 32;
            unsigned char ebuf[70];
            unsigned long elen2 = sizeof(ebuf);
            big_to_bytes(ebuf, &elen2, elems[i]);
            /* pad to 32 bytes */
            if (elen2 < 32) {
                unsigned long pad = 32 - elen2;
                unsigned long k;
                for (k = 0; k < pad && wlen < sizeof(wbuf); k++)
                    wbuf[wlen++] = 0;
                for (k = 0; k < elen2 && wlen < sizeof(wbuf); k++)
                    wbuf[wlen++] = ebuf[k];
            } else {
                unsigned long k;
                for (k = 0; k < elen && wlen < sizeof(wbuf); k++)
                    wbuf[wlen++] = ebuf[k];
            }
        }
    }

    /* h = H2(M || w) */
    zbuflen = msglen + wlen;
    zbuf = (unsigned char*)malloc(zbuflen);
    if (!zbuf) goto retry;
    memcpy(zbuf, msg, msglen);
    memcpy(zbuf + msglen, wbuf, wlen);
    sm9_hash_to_range(&hh, 0x02, zbuf, zbuflen);
    free(zbuf);

    /* l = (r - h) mod N */
    big_sub(&tmp, &r, &hh);
    if (big_cmp(&tmp, &sm9_zero) < 0) {
        big_add(&l, &tmp, &sm9_n);
    } else {
        big_set(&l, &tmp);
    }
    big_mod(&l, &l, &sm9_n);

    if (big_cmp(&l, &sm9_zero) == 0) {
        goto retry;
    }

    /* S = l * dA */
    g1_scalar_mult(S, uk, &l);

    /* Output h as 32 bytes */
    {
        unsigned long hlen = sizeof(wbuf);
        big_to_bytes(wbuf, &hlen, &hh);
        memset(h, 0, 32);
        if (hlen <= 32) {
            memcpy(h + (32 - hlen), wbuf, hlen);
        } else {
            memcpy(h, wbuf, 32);
        }
    }

    big_destroy(&r); big_destroy(&hh); big_destroy(&l); big_destroy(&tmp);
}

int sm9_verify(const unsigned char h[32], const sm9_g1_t* S,
               const unsigned char* msg, unsigned long msglen,
               const unsigned char* id, unsigned long idlen,
               const sm9_g2_t* Ppub) {
    big_t hh, h1;
    fp12_t t, u, w;
    sm9_g2_t P_id;
    unsigned char wbuf[384];
    unsigned char* zbuf;
    unsigned long zbuflen, wlen;
    unsigned long i;
    big_t h_prime;
    int ret = 0;

    big_init(&hh); big_init(&h1); big_init(&h_prime);

    big_from_bytes(&hh, (unsigned char*)h, 32);

    /* Check h in [1, N-1] */
    if (big_cmp(&hh, &sm9_one) < 0 || big_cmp(&hh, &sm9_n) >= 0) {
        big_destroy(&hh); big_destroy(&h1); big_destroy(&h_prime);
        return 0;
    }

    /* t = g^h where g = e(P1, Ppub) */
    fp12_t g;
    sm9_pairing(&g, &sm9_P1, Ppub);
    fp12_pow(&t, &g, &hh);

    /* h1 = H1(IDA || hid) */
    zbuflen = idlen + 1;
    zbuf = (unsigned char*)malloc(zbuflen);
    if (!zbuf) goto cleanup;
    memcpy(zbuf, id, idlen);
    zbuf[idlen] = 0x01;
    sm9_hash_to_range(&h1, 0x01, zbuf, zbuflen);
    free(zbuf);
    zbuf = NULL;

    /* P = h1 * P2 + Ppub */
    g2_scalar_mult(&P_id, &sm9_P2, &h1);
    g2_add(&P_id, &P_id, Ppub);

    /* u = e(S', P) */
    sm9_pairing(&u, S, &P_id);

    /* w' = u * t */
    fp12_mul(&w, &u, &t);

    /* Serialize w' */
    wlen = 0;
    {
        big_t* elems[12] = {
            &w.a0.a0.a0, &w.a0.a0.a1, &w.a0.a1.a0, &w.a0.a1.a1,
            &w.a1.a0.a0, &w.a1.a0.a1, &w.a1.a1.a0, &w.a1.a1.a1,
            &w.a2.a0.a0, &w.a2.a0.a1, &w.a2.a1.a0, &w.a2.a1.a1
        };
        for (i = 0; i < 12; i++) {
            unsigned long elen = 32;
            unsigned char ebuf[70];
            unsigned long elen2 = sizeof(ebuf);
            big_to_bytes(ebuf, &elen2, elems[i]);
            if (elen2 < 32) {
                unsigned long pad = 32 - elen2;
                unsigned long k;
                for (k = 0; k < pad && wlen < sizeof(wbuf); k++)
                    wbuf[wlen++] = 0;
                for (k = 0; k < elen2 && wlen < sizeof(wbuf); k++)
                    wbuf[wlen++] = ebuf[k];
            } else {
                unsigned long k;
                for (k = 0; k < elen && wlen < sizeof(wbuf); k++)
                    wbuf[wlen++] = ebuf[k];
            }
        }
    }

    /* h2 = H2(M || w') */
    zbuflen = msglen + wlen;
    zbuf = (unsigned char*)malloc(zbuflen);
    if (!zbuf) goto cleanup;
    memcpy(zbuf, msg, msglen);
    memcpy(zbuf + msglen, wbuf, wlen);
    sm9_hash_to_range(&h_prime, 0x02, zbuf, zbuflen);
    free(zbuf);
    zbuf = NULL;

    ret = (big_cmp(&hh, &h_prime) == 0);

cleanup:
    big_destroy(&hh); big_destroy(&h1); big_destroy(&h_prime);
    return ret;
}

/* ── SM9 Encrypt / Decrypt ────────────────────────────────────────── */

int sm9_encrypt(unsigned char* ct, unsigned long ctsize, unsigned long* ctlen,
                const unsigned char* msg, unsigned long msglen,
                const unsigned char* id, unsigned long idlen,
                const sm9_enc_master_key_t* mk) {
    big_t h1, r, tmp;
    sm9_g1_t C1, QB;
    fp12_t g, w;
    unsigned char *kbuf; /* K1(msglen) + K2(32), per GB/T 38635.2 */
    unsigned char* zbuf;
    unsigned long zbuflen;
    unsigned long c1len, i;
    sm3_context_t sm3_ctx;

    /* Minimum output: 65(C1) + msglen(C2) + 32(C3) */
    if (ctsize < 65 + msglen + 32) return 0;

    big_init(&h1); big_init(&r); big_init(&tmp);

    kbuf = (unsigned char*)malloc(msglen + 32);
    if (!kbuf) { big_destroy(&h1); big_destroy(&r); big_destroy(&tmp); return 0; }

    /* QB = H1(IDB||hid)*P1 + Ppub_e */
    zbuflen = idlen + 1;
    zbuf = (unsigned char*)malloc(zbuflen);
    if (!zbuf) { big_destroy(&h1); big_destroy(&r); big_destroy(&tmp); return 0; }
    memcpy(zbuf, id, idlen);
    zbuf[idlen] = 0x03;
    sm9_hash_to_range(&h1, 0x01, zbuf, zbuflen);
    free(zbuf);

    g1_scalar_mult(&QB, &sm9_P1, &h1);
    g1_add(&QB, &QB, &mk->Ppub);

    /* random r */
    big_rand(&r, 256);
    big_sub(&tmp, &sm9_n, &sm9_two);
    big_mod(&r, &r, &tmp);
    big_add(&tmp, &r, &sm9_one);
    big_set(&r, &tmp);

    /* C1 = r * QB */
    g1_scalar_mult(&C1, &QB, &r);

    /* g = e(Ppub_e, P2) */
    sm9_pairing(&g, &mk->Ppub, &sm9_P2);

    /* w = g^r */
    fp12_pow(&w, &g, &r);

    /* Derive key: K = KDF(C1||w||IDB, klen) */
    /* Serialize C1 (uncompressed: 04 || x || y) */
    {
        unsigned char c1_ser[65];
        unsigned long blen;
        c1_ser[0] = 0x04;
        blen = 32;
        big_to_bytes(c1_ser + 1, &blen, &C1.x);
        if (blen < 32) {
            memmove(c1_ser + 1 + (32 - blen), c1_ser + 1, blen);
            memset(c1_ser + 1, 0, 32 - blen);
        }
        blen = 32;
        big_to_bytes(c1_ser + 33, &blen, &C1.y);
        if (blen < 32) {
            memmove(c1_ser + 33 + (32 - blen), c1_ser + 33, blen);
            memset(c1_ser + 33, 0, 32 - blen);
        }
        c1len = 65;

        /* KDF input: C1 || w (serialized 384 bytes) || IDB */
        unsigned long kdf_input_len = c1len + 384 + idlen;
        unsigned char* kdf_input = (unsigned char*)malloc(kdf_input_len);
        if (!kdf_input) { big_destroy(&h1); big_destroy(&r); big_destroy(&tmp); return 0; }
        memcpy(kdf_input, c1_ser, c1len);

        /* Serialize w */
        unsigned long woff = c1len;
        big_t* elems[12] = {
            &w.a0.a0.a0, &w.a0.a0.a1, &w.a0.a1.a0, &w.a0.a1.a1,
            &w.a1.a0.a0, &w.a1.a0.a1, &w.a1.a1.a0, &w.a1.a1.a1,
            &w.a2.a0.a0, &w.a2.a0.a1, &w.a2.a1.a0, &w.a2.a1.a1
        };
        for (i = 0; i < 12; i++) {
            unsigned char ebuf[70];
            unsigned long elen = sizeof(ebuf);
            big_to_bytes(ebuf, &elen, elems[i]);
            if (elen < 32) {
                memset(kdf_input + woff, 0, 32 - elen);
                memcpy(kdf_input + woff + (32 - elen), ebuf, elen);
            } else {
                memcpy(kdf_input + woff, ebuf, 32);
            }
            woff += 32;
        }
        memcpy(kdf_input + woff, id, idlen);

        /* K1 = first msglen bytes, K2 = next 32 bytes (per GB/T 38635.2) */
        sm9_kdf(kbuf, msglen + 32, kdf_input, kdf_input_len);
        free(kdf_input);

        /* C1 in output */
        memcpy(ct, c1_ser, 65);
    }

    /* C2 = M xor K1 (per GB/T 38635.2, K1 has msglen bytes) */
    for (i = 0; i < msglen; i++) {
        ct[65 + i] = msg[i] ^ kbuf[i];
    }

    /* C3 = MAC(K2, C2) per GB/T 38635.2 — MAC over ciphertext */
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, kbuf + msglen, 32);
    sm3_update(&sm3_ctx, ct + 65, msglen);
    sm3_finish(&sm3_ctx, ct + 65 + msglen);

    *ctlen = 65 + msglen + 32;

    secure_wipe(kbuf, msglen + 32);
    free(kbuf);
    big_destroy(&h1); big_destroy(&r); big_destroy(&tmp);
    return 1;
}

int sm9_decrypt(unsigned char* msg, unsigned long msgsize, unsigned long* msglen,
                const unsigned char* ct, unsigned long ctlen,
                const unsigned char* id, unsigned long idlen,
                const sm9_enc_user_key_t* uk) {
    sm9_g1_t C1;
    fp12_t w;
    unsigned char *kbuf;
    unsigned char mac[32];
    sm3_context_t sm3_ctx;
    unsigned long i, mlen;

    if (ctlen < 65 + 32) return 0;
    mlen = ctlen - 65 - 32;
    if (msgsize < mlen) return 0;

    kbuf = (unsigned char*)malloc(mlen + 32);
    if (!kbuf) return 0;

    /* Parse C1 */
    if (ct[0] != 0x04) return 0;
    big_from_bytes(&C1.x, (unsigned char*)ct + 1, 32);
    big_from_bytes(&C1.y, (unsigned char*)ct + 33, 32);

    if (!g1_on_curve(&C1)) { free(kbuf); return 0; }

    /* w = e(C1, de) where de is user decryption key (G2 point) */
    sm9_pairing(&w, &C1, uk);

    /* KDF */
    {
        unsigned long kdf_input_len = 65 + 384 + idlen;
        unsigned char* kdf_input = (unsigned char*)malloc(kdf_input_len);
        if (!kdf_input) { free(kbuf); return 0; }
        memcpy(kdf_input, ct, 65);

        unsigned long woff = 65;
        big_t* elems[12] = {
            &w.a0.a0.a0, &w.a0.a0.a1, &w.a0.a1.a0, &w.a0.a1.a1,
            &w.a1.a0.a0, &w.a1.a0.a1, &w.a1.a1.a0, &w.a1.a1.a1,
            &w.a2.a0.a0, &w.a2.a0.a1, &w.a2.a1.a0, &w.a2.a1.a1
        };
        for (i = 0; i < 12; i++) {
            unsigned char ebuf[70];
            unsigned long elen = sizeof(ebuf);
            big_to_bytes(ebuf, &elen, elems[i]);
            if (elen < 32) {
                memset(kdf_input + woff, 0, 32 - elen);
                memcpy(kdf_input + woff + (32 - elen), ebuf, elen);
            } else {
                memcpy(kdf_input + woff, ebuf, 32);
            }
            woff += 32;
        }
        memcpy(kdf_input + woff, id, idlen);
        sm9_kdf(kbuf, mlen + 32, kdf_input, kdf_input_len);
        free(kdf_input);
    }

    /* Verify C3 = MAC(K2, C2) per GB/T 38635.2 — BEFORE decrypting */
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, kbuf + mlen, 32);
    sm3_update(&sm3_ctx, ct + 65, mlen);
    sm3_finish(&sm3_ctx, mac);

    if (ct_memcmp(mac, ct + 65 + mlen, 32) != 0) {
        secure_wipe(kbuf, mlen + 32);
        free(kbuf);
        return 0;
    }

    /* Decrypt C2 only after MAC verification passes */
    for (i = 0; i < mlen; i++) {
        msg[i] = ct[65 + i] ^ kbuf[i];
    }

    *msglen = mlen;

    secure_wipe(kbuf, mlen + 32);
    free(kbuf);
    return 1;
}

/* ── SM9 Key Exchange ─────────────────────────────────────────────── */

void sm9_key_exchange_init(sm9_g1_t* R, big_t* r,
                           const sm9_enc_master_key_t* mk) {
    big_t tmp;
    big_init(&tmp);
    (void)mk;

    /* r random in [1, N-1] */
    big_rand(r, 256);
    big_sub(&tmp, &sm9_n, &sm9_two);
    big_mod(r, r, &tmp);
    big_add(&tmp, r, &sm9_one);
    big_set(r, &tmp);

    /* R = r * Ppub_e (or r * QB depending on role) */
    /* Simplified: R = r * P1 */
    g1_scalar_mult(R, &sm9_P1, r);

    big_destroy(&tmp);
}

int sm9_key_exchange_finish(unsigned char* sk, unsigned long sklen,
                            int is_init,
                            const unsigned char* id_self,
                            unsigned long id_self_len,
                            const unsigned char* id_peer,
                            unsigned long id_peer_len,
                            const sm9_enc_user_key_t* uk,
                            const big_t* r,
                            const sm9_g1_t* R_self,
                            const sm9_g1_t* R_peer,
                            const sm9_enc_master_key_t* mk) {
    fp12_t g1, g2, g3;
    unsigned char* kdf_input;
    unsigned long kdf_len;
    unsigned long off = 0;
    unsigned long i;

    (void)is_init;
    (void)uk;
    (void)r;

    /* Compute pairing values */
    sm9_pairing(&g1, R_peer, &sm9_P2);  /* e(R_peer, P2) */
    sm9_pairing(&g2, &mk->Ppub, &sm9_P2);  /* e(Ppub, P2) */
    fp12_mul(&g3, &g1, &g2);

    /* Build KDF input: IDA || IDB || R_A || R_B || g */
    kdf_len = id_self_len + id_peer_len + 65 + 65 + 384;
    kdf_input = (unsigned char*)malloc(kdf_len);
    if (!kdf_input) return 0;

    memcpy(kdf_input + off, id_self, id_self_len); off += id_self_len;
    memcpy(kdf_input + off, id_peer, id_peer_len); off += id_peer_len;

    /* Serialize R_self */
    {
        unsigned long blen;
        kdf_input[off++] = 0x04;
        blen = 32;
        unsigned char tbuf[70];
        unsigned long tlen = sizeof(tbuf);
        big_to_bytes(tbuf, &tlen, &R_self->x);
        if (tlen < 32) { memset(kdf_input + off, 0, 32 - tlen); memcpy(kdf_input + off + (32 - tlen), tbuf, tlen); }
        else memcpy(kdf_input + off, tbuf, 32);
        off += 32;
        tlen = sizeof(tbuf);
        big_to_bytes(tbuf, &tlen, &R_self->y);
        if (tlen < 32) { memset(kdf_input + off, 0, 32 - tlen); memcpy(kdf_input + off + (32 - tlen), tbuf, tlen); }
        else memcpy(kdf_input + off, tbuf, 32);
        off += 32;
        (void)blen;
    }

    /* Serialize R_peer */
    {
        unsigned long blen;
        kdf_input[off++] = 0x04;
        unsigned char tbuf[70];
        unsigned long tlen = sizeof(tbuf);
        big_to_bytes(tbuf, &tlen, &R_peer->x);
        if (tlen < 32) { memset(kdf_input + off, 0, 32 - tlen); memcpy(kdf_input + off + (32 - tlen), tbuf, tlen); }
        else memcpy(kdf_input + off, tbuf, 32);
        off += 32;
        tlen = sizeof(tbuf);
        big_to_bytes(tbuf, &tlen, &R_peer->y);
        if (tlen < 32) { memset(kdf_input + off, 0, 32 - tlen); memcpy(kdf_input + off + (32 - tlen), tbuf, tlen); }
        else memcpy(kdf_input + off, tbuf, 32);
        off += 32;
        (void)blen;
    }

    /* Serialize g3 (Fp12, 12*32=384 bytes) */
    {
        big_t* elems[12] = {
            &g3.a0.a0.a0, &g3.a0.a0.a1, &g3.a0.a1.a0, &g3.a0.a1.a1,
            &g3.a1.a0.a0, &g3.a1.a0.a1, &g3.a1.a1.a0, &g3.a1.a1.a1,
            &g3.a2.a0.a0, &g3.a2.a0.a1, &g3.a2.a1.a0, &g3.a2.a1.a1
        };
        for (i = 0; i < 12; i++) {
            unsigned char ebuf[70];
            unsigned long elen = sizeof(ebuf);
            big_to_bytes(ebuf, &elen, elems[i]);
            if (elen < 32) {
                memset(kdf_input + off, 0, 32 - elen);
                memcpy(kdf_input + off + (32 - elen), ebuf, elen);
            } else {
                memcpy(kdf_input + off, ebuf, 32);
            }
            off += 32;
        }
    }

    sm9_kdf(sk, sklen, kdf_input, off);
    free(kdf_input);

    (void)mk;
    return 1;
}

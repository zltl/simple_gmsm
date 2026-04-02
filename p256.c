#include "simple_gmsm/sm2.h"
#include "simple_gmsm/big.h"

#ifndef USE_SLOW_BIGINT
#include "montgomery.h"
#endif

#define SM2_MAX_BIG_BYTES 70

/* 参数定义 */
/* y^2 = x^3 + ax + b */

unsigned char _p[] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char _a[] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
unsigned char _b[] = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
                      0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
                      0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
                      0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};
unsigned char _n[] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
                      0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23};
unsigned char _gx[] = {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
                       0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
                       0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
                       0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};
unsigned char _gy[] = {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
                       0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
                       0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
                       0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};
// 余因子是1
/*
static unsigned char _h[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
*/

// w = log2(n)/2-1
// 2^2
unsigned char _2w[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 2^w-1
unsigned char _2w_1[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

unsigned char _zeros[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* 参数对应的大整数结构 */
big_t sm2_p, sm2_a, sm2_b, sm2_n, sm2_gx, sm2_gy;
big_t sm2_d_max;
big_t sm2_2w, sm2_2w_1;

#ifndef USE_SLOW_BIGINT
static sgmsm_mont_ctx_t sm2_fp_ctx;
static big_t sm2_a_field;
static big_t sm2_b_field;
#endif

static void sm2_fp_from_std(big_t* out, const big_t* a) {
#ifndef USE_SLOW_BIGINT
    sgmsm_mont_from_std(out, a, &sm2_fp_ctx);
#else
    big_set(out, a);
#endif
}

static void sm2_fp_to_std(big_t* out, const big_t* a) {
#ifndef USE_SLOW_BIGINT
    sgmsm_mont_to_std(out, a, &sm2_fp_ctx);
#else
    big_set(out, a);
#endif
}

static void sm2_fp_set_one(big_t* out) {
#ifndef USE_SLOW_BIGINT
    big_set(out, &sm2_fp_ctx.one);
#else
    big_set(out, &big_one);
#endif
}

static void sm2_fp_add(big_t* out, const big_t* a, const big_t* b) {
    big_add(out, a, b);
    if (big_cmp(out, &sm2_p) >= 0) {
        big_sub(out, out, &sm2_p);
    }
}

static void sm2_fp_sub(big_t* out, const big_t* a, const big_t* b) {
    big_sub(out, a, b);
    if (big_cmp(out, &big_zero) < 0) {
        big_add(out, out, &sm2_p);
    }
}

static void sm2_fp_mul(big_t* out, const big_t* a, const big_t* b) {
#ifndef USE_SLOW_BIGINT
    sgmsm_mont_mul(out, a, b, &sm2_fp_ctx);
#else
    SM_STATIC big_t tmp;

    big_init(&tmp);
    big_mul(&tmp, a, b);
    big_mod(out, &tmp, &sm2_p);
    big_destroy(&tmp);
#endif
}

static void sm2_fp_sqr(big_t* out, const big_t* a) {
#ifndef USE_SLOW_BIGINT
    sgmsm_mont_sqr(out, a, &sm2_fp_ctx);
#else
    sm2_fp_mul(out, a, a);
#endif
}

static void sm2_fp_inv(big_t* out, const big_t* a) {
#ifndef USE_SLOW_BIGINT
    sgmsm_mont_inv(out, a, &sm2_fp_ctx);
#else
    big_inv(out, a, &sm2_p);
#endif
}

static void sm2_get_jacobian_z_field(big_t* z, const big_t* x,
                                     const big_t* y) {
    if (big_cmp(x, &big_zero) != 0 && big_cmp(y, &big_zero) != 0) {
        sm2_fp_set_one(z);
    } else {
        big_set(z, &big_zero);
    }
}

static void sm2_double_jacobian_field(big_t* x3, big_t* y3, big_t* z3,
                                      const big_t* x1, const big_t* y1,
                                      const big_t* z1);

static void sm2_jacobian_to_affine_field(big_t* xout, big_t* yout,
                                         const big_t* x, const big_t* y,
                                         const big_t* z) {
    SM_STATIC big_t zinv, zinvsq, zinvcu, rx, ry;

    if (big_cmp(z, &big_zero) == 0) {
        big_set(xout, &big_zero);
        big_set(yout, &big_zero);
        return;
    }

    big_init(&zinv);
    big_init(&zinvsq);
    big_init(&zinvcu);
    big_init(&rx);
    big_init(&ry);

    sm2_fp_inv(&zinv, z);
    sm2_fp_sqr(&zinvsq, &zinv);
    sm2_fp_mul(&rx, x, &zinvsq);
    sm2_fp_mul(&zinvcu, &zinvsq, &zinv);
    sm2_fp_mul(&ry, y, &zinvcu);

    sm2_fp_to_std(xout, &rx);
    sm2_fp_to_std(yout, &ry);

    big_destroy(&zinv);
    big_destroy(&zinvsq);
    big_destroy(&zinvcu);
    big_destroy(&rx);
    big_destroy(&ry);
}

static void sm2_add_jacobian_field(big_t* x3, big_t* y3, big_t* z3,
                                   const big_t* x1, const big_t* y1,
                                   const big_t* z1, const big_t* x2,
                                   const big_t* y2, const big_t* z2) {
    SM_STATIC big_t z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v;
    SM_STATIC big_t tmp1, tmp2;

    if (big_cmp(z1, &big_zero) == 0) {
        big_set(x3, x2);
        big_set(y3, y2);
        big_set(z3, z2);
        return;
    }
    if (big_cmp(z2, &big_zero) == 0) {
        big_set(x3, x1);
        big_set(y3, y1);
        big_set(z3, z1);
        return;
    }

    big_init(&z1z1);
    big_init(&z2z2);
    big_init(&u1);
    big_init(&u2);
    big_init(&s1);
    big_init(&s2);
    big_init(&h);
    big_init(&i);
    big_init(&j);
    big_init(&r);
    big_init(&v);
    big_init(&tmp1);
    big_init(&tmp2);

    sm2_fp_sqr(&z1z1, z1);
    sm2_fp_sqr(&z2z2, z2);
    sm2_fp_mul(&u1, x1, &z2z2);
    sm2_fp_mul(&u2, x2, &z1z1);

    sm2_fp_mul(&tmp1, y1, z2);
    sm2_fp_mul(&s1, &tmp1, &z2z2);
    sm2_fp_mul(&tmp1, y2, z1);
    sm2_fp_mul(&s2, &tmp1, &z1z1);

    if (big_cmp(&u1, &u2) == 0) {
        int points_equal = (big_cmp(&s1, &s2) == 0);

        big_destroy(&z1z1);
        big_destroy(&z2z2);
        big_destroy(&u1);
        big_destroy(&u2);
        big_destroy(&s1);
        big_destroy(&s2);
        big_destroy(&h);
        big_destroy(&i);
        big_destroy(&j);
        big_destroy(&r);
        big_destroy(&v);
        big_destroy(&tmp1);
        big_destroy(&tmp2);

        if (points_equal) {
            sm2_double_jacobian_field(x3, y3, z3, x1, y1, z1);
        } else {
            big_set(x3, &big_zero);
            big_set(y3, &big_zero);
            big_set(z3, &big_zero);
        }
        return;
    }

    sm2_fp_sub(&h, &u2, &u1);
    sm2_fp_add(&tmp1, &h, &h);
    sm2_fp_sqr(&i, &tmp1);
    sm2_fp_mul(&j, &h, &i);

    sm2_fp_sub(&tmp1, &s2, &s1);
    sm2_fp_add(&r, &tmp1, &tmp1);
    sm2_fp_mul(&v, &u1, &i);

    sm2_fp_sqr(&tmp1, &r);
    sm2_fp_add(&tmp2, &v, &v);
    sm2_fp_sub(&tmp1, &tmp1, &j);
    sm2_fp_sub(x3, &tmp1, &tmp2);

    sm2_fp_sub(&tmp1, &v, x3);
    sm2_fp_mul(&tmp2, &r, &tmp1);
    sm2_fp_add(&tmp1, &s1, &s1);
    sm2_fp_mul(&tmp1, &tmp1, &j);
    sm2_fp_sub(y3, &tmp2, &tmp1);

    sm2_fp_add(&tmp1, z1, z2);
    sm2_fp_sqr(&tmp2, &tmp1);
    sm2_fp_sub(&tmp2, &tmp2, &z1z1);
    sm2_fp_sub(&tmp2, &tmp2, &z2z2);
    sm2_fp_mul(z3, &tmp2, &h);

    big_destroy(&z1z1);
    big_destroy(&z2z2);
    big_destroy(&u1);
    big_destroy(&u2);
    big_destroy(&s1);
    big_destroy(&s2);
    big_destroy(&h);
    big_destroy(&i);
    big_destroy(&j);
    big_destroy(&r);
    big_destroy(&v);
    big_destroy(&tmp1);
    big_destroy(&tmp2);
}

static void sm2_double_jacobian_field(big_t* x3, big_t* y3, big_t* z3,
                                      const big_t* x1, const big_t* y1,
                                      const big_t* z1) {
    SM_STATIC big_t delta, gamma, beta, alpha, alpha2;
    SM_STATIC big_t tmp1, tmp2;

    if (big_cmp(z1, &big_zero) == 0 || big_cmp(y1, &big_zero) == 0) {
        big_set(x3, &big_zero);
        big_set(y3, &big_zero);
        big_set(z3, &big_zero);
        return;
    }

    big_init(&delta);
    big_init(&gamma);
    big_init(&beta);
    big_init(&alpha);
    big_init(&alpha2);
    big_init(&tmp1);
    big_init(&tmp2);

    sm2_fp_sqr(&delta, z1);
    sm2_fp_sqr(&gamma, y1);
    sm2_fp_mul(&beta, x1, &gamma);

    sm2_fp_sub(&tmp1, x1, &delta);
    sm2_fp_add(&tmp2, x1, &delta);
    sm2_fp_mul(&alpha, &tmp1, &tmp2);
    sm2_fp_add(&tmp1, &alpha, &alpha);
    sm2_fp_add(&alpha, &tmp1, &alpha);

    sm2_fp_sqr(&alpha2, &alpha);
    sm2_fp_add(&tmp1, &beta, &beta);
    sm2_fp_add(&tmp1, &tmp1, &tmp1);
    sm2_fp_add(&tmp1, &tmp1, &tmp1);
    sm2_fp_sub(x3, &alpha2, &tmp1);

    sm2_fp_add(&tmp1, y1, z1);
    sm2_fp_sqr(&tmp2, &tmp1);
    sm2_fp_sub(&tmp2, &tmp2, &gamma);
    sm2_fp_sub(z3, &tmp2, &delta);

    sm2_fp_add(&tmp1, &beta, &beta);
    sm2_fp_add(&tmp1, &tmp1, &tmp1);
    sm2_fp_sub(&tmp1, &tmp1, x3);
    sm2_fp_mul(&tmp2, &alpha, &tmp1);

    sm2_fp_sqr(&delta, &gamma);
    sm2_fp_add(&tmp1, &delta, &delta);
    sm2_fp_add(&tmp1, &tmp1, &tmp1);
    sm2_fp_add(&tmp1, &tmp1, &tmp1);
    sm2_fp_sub(y3, &tmp2, &tmp1);

    big_destroy(&delta);
    big_destroy(&gamma);
    big_destroy(&beta);
    big_destroy(&alpha);
    big_destroy(&alpha2);
    big_destroy(&tmp1);
    big_destroy(&tmp2);
}

void sm2_init(void) {
    big_init(&sm2_p);
    big_init(&sm2_a);
    big_init(&sm2_b);
    big_init(&sm2_n);
    big_init(&sm2_gx);
    big_init(&sm2_gy);
    big_init(&sm2_d_max);
    big_init(&sm2_2w);
    big_init(&sm2_2w_1);

    big_from_bytes(&sm2_p, _p, sizeof(_p));
    big_from_bytes(&sm2_a, _a, sizeof(_a));
    big_from_bytes(&sm2_b, _b, sizeof(_b));
    big_from_bytes(&sm2_n, _n, sizeof(_n));
    big_from_bytes(&sm2_gx, _gx, sizeof(_gx));
    big_from_bytes(&sm2_gy, _gy, sizeof(_gy));
    big_sub(&sm2_d_max, &sm2_n, &big_two);  // private key d in [1, n-2]
    big_from_bytes(&sm2_2w, _2w, sizeof(_2w));
    big_from_bytes(&sm2_2w_1, _2w_1, sizeof(_2w_1));

#ifndef USE_SLOW_BIGINT
    big_init(&sm2_a_field);
    big_init(&sm2_b_field);
    sgmsm_mont_init(&sm2_fp_ctx, &sm2_p);
    sm2_fp_from_std(&sm2_a_field, &sm2_a);
    sm2_fp_from_std(&sm2_b_field, &sm2_b);
#endif
}

void sm2_destroy(void) {
#ifndef USE_SLOW_BIGINT
    big_destroy(&sm2_a_field);
    big_destroy(&sm2_b_field);
    sgmsm_mont_destroy(&sm2_fp_ctx);
#endif

    big_destroy(&sm2_p);
    big_destroy(&sm2_a);
    big_destroy(&sm2_b);
    big_destroy(&sm2_n);
    big_destroy(&sm2_gx);
    big_destroy(&sm2_gy);
    big_destroy(&sm2_d_max);
    big_destroy(&sm2_2w);
    big_destroy(&sm2_2w_1);
}

// This file operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform. But even for Add and
// Double, it's faster to apply and reverse the transform than to operate
// in affine coordinates.

// returns a Jacobian Z value for the affine point (x, y)
// usually we use (x, y, 1) as Jacobian point because it's easy to get.
// value (4x, 8y, 2) or (9x, 27y, 3) are alternative, but hard to generate.
// If x and y are zero, it assumes that they represent the point at infinity
// because (0, 0) is not on the any of the curves handled here.
void sm2_get_jacobian_z(big_t* z, const big_t* x, const big_t* y) {
    if (big_cmp(x, &big_zero) != 0 && big_cmp(y, &big_zero) != 0) {
        big_set(z, &big_one);
    } else {
        big_set(z, &big_zero);
    }
}

// reverses the Jacobian transform. If the point is ∞ it returns 0, 0.
void sm2_jacobian_to_affine(big_t* xout, big_t* yout, const big_t* x,
                            const big_t* y, const big_t* z) {
    SM_STATIC big_t fx, fy, fz;

    big_init(&fx);
    big_init(&fy);
    big_init(&fz);

    sm2_fp_from_std(&fx, x);
    sm2_fp_from_std(&fy, y);
    sm2_fp_from_std(&fz, z);
    sm2_jacobian_to_affine_field(xout, yout, &fx, &fy, &fz);

    big_destroy(&fx);
    big_destroy(&fy);
    big_destroy(&fz);
}

// takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, in Jacobian form.
// See
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
/*
      Z1Z1 = Z1^2
      Z2Z2 = Z2^2
      U1 = X1*Z2Z2
      U2 = X2*Z1Z1
      S1 = Y1*Z2*Z2Z2
      S2 = Y2*Z1*Z1Z1
      H = U2-U1
      I = (2*H)^2
      J = H*I
      r = 2*(S2-S1)
      V = U1*I
      X3 = r^2-J-2*V
      Y3 = r*(V-X3)-2*S1*J
      Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
*/
void sm2_add_jocabian(big_t* x3, big_t* y3, big_t* z3, const big_t* x1,
                      const big_t* y1, const big_t* z1, const big_t* x2,
                      const big_t* y2, const big_t* z2) {
    SM_STATIC big_t fx1, fy1, fz1, fx2, fy2, fz2;
    SM_STATIC big_t fx3, fy3, fz3;

    big_init(&fx1);
    big_init(&fy1);
    big_init(&fz1);
    big_init(&fx2);
    big_init(&fy2);
    big_init(&fz2);
    big_init(&fx3);
    big_init(&fy3);
    big_init(&fz3);

    sm2_fp_from_std(&fx1, x1);
    sm2_fp_from_std(&fy1, y1);
    sm2_fp_from_std(&fz1, z1);
    sm2_fp_from_std(&fx2, x2);
    sm2_fp_from_std(&fy2, y2);
    sm2_fp_from_std(&fz2, z2);

    sm2_add_jacobian_field(&fx3, &fy3, &fz3, &fx1, &fy1, &fz1, &fx2, &fy2,
                           &fz2);

    sm2_fp_to_std(x3, &fx3);
    sm2_fp_to_std(y3, &fy3);
    sm2_fp_to_std(z3, &fz3);

    big_destroy(&fx1);
    big_destroy(&fy1);
    big_destroy(&fz1);
    big_destroy(&fx2);
    big_destroy(&fy2);
    big_destroy(&fz2);
    big_destroy(&fx3);
    big_destroy(&fy3);
    big_destroy(&fz3);
}

/* point P1+P2 */
void sm2_add(big_t* x3, big_t* y3, big_t* x1, big_t* y1, big_t* x2,
             big_t* y2) {
    SM_STATIC big_t fx1, fy1, fx2, fy2;
    SM_STATIC big_t z1, z2, z3;
    SM_STATIC big_t tx, ty;

    big_init(&fx1);
    big_init(&fy1);
    big_init(&fx2);
    big_init(&fy2);
    big_init(&z1);
    big_init(&z2);
    big_init(&z3);
    big_init(&tx);
    big_init(&ty);

    sm2_fp_from_std(&fx1, x1);
    sm2_fp_from_std(&fy1, y1);
    sm2_fp_from_std(&fx2, x2);
    sm2_fp_from_std(&fy2, y2);

    sm2_get_jacobian_z_field(&z1, &fx1, &fy1);
    sm2_get_jacobian_z_field(&z2, &fx2, &fy2);
    sm2_add_jacobian_field(&tx, &ty, &z3, &fx1, &fy1, &z1, &fx2, &fy2, &z2);
    sm2_jacobian_to_affine_field(x3, y3, &tx, &ty, &z3);

    big_destroy(&fx1);
    big_destroy(&fy1);
    big_destroy(&fx2);
    big_destroy(&fy2);
    big_destroy(&z1);
    big_destroy(&z2);
    big_destroy(&z3);
    big_destroy(&tx);
    big_destroy(&ty);
}

// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
/*
      delta = Z1^2
      gamma = Y1^2
      beta = X1*gamma
      alpha = 3*(X1-delta)*(X1+delta)
      X3 = alpha^2-8*beta
      Z3 = (Y1+Z1)^2-gamma-delta
      Y3 = alpha*(4*beta-X3)-8*gamma^2
*/
void sm2_double_jacobian(big_t* x3, big_t* y3, big_t* z3, const big_t* x1,
                         const big_t* y1, const big_t* z1) {
    SM_STATIC big_t fx1, fy1, fz1, fx3, fy3, fz3;

    big_init(&fx1);
    big_init(&fy1);
    big_init(&fz1);
    big_init(&fx3);
    big_init(&fy3);
    big_init(&fz3);

    sm2_fp_from_std(&fx1, x1);
    sm2_fp_from_std(&fy1, y1);
    sm2_fp_from_std(&fz1, z1);
    sm2_double_jacobian_field(&fx3, &fy3, &fz3, &fx1, &fy1, &fz1);

    sm2_fp_to_std(x3, &fx3);
    sm2_fp_to_std(y3, &fy3);
    sm2_fp_to_std(z3, &fz3);

    big_destroy(&fx1);
    big_destroy(&fy1);
    big_destroy(&fz1);
    big_destroy(&fx3);
    big_destroy(&fy3);
    big_destroy(&fz3);
}

void sm2_double(big_t* x3, big_t* y3, big_t* x1, big_t* y1) {
    SM_STATIC big_t fx1, fy1;
    SM_STATIC big_t z1, z3;
    SM_STATIC big_t tx, ty;

    big_init(&fx1);
    big_init(&fy1);
    big_init(&z1);
    big_init(&z3);
    big_init(&tx);
    big_init(&ty);

    sm2_fp_from_std(&fx1, x1);
    sm2_fp_from_std(&fy1, y1);
    sm2_get_jacobian_z_field(&z1, &fx1, &fy1);
    sm2_double_jacobian_field(&tx, &ty, &z3, &fx1, &fy1, &z1);
    sm2_jacobian_to_affine_field(x3, y3, &tx, &ty, &z3);

    big_destroy(&fx1);
    big_destroy(&fy1);
    big_destroy(&z1);
    big_destroy(&z3);
    big_destroy(&tx);
    big_destroy(&ty);
}

// (x3, y3) <- k * P(gx, gy)
void sm2_scalar_mult(big_t* x3, big_t* y3, const big_t* bx, const big_t* by,
                     const big_t* k) {
    SM_STATIC big_t fbx, fby, bz;
    SM_STATIC big_t rx, ry, rz;
    unsigned long i, j, byte;
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES];
    unsigned long len = sizeof(buf);

    big_init(&fbx);
    big_init(&fby);
    big_init(&bz);
    big_init(&rx);
    big_init(&ry);
    big_init(&rz);

    sm2_fp_from_std(&fbx, bx);
    sm2_fp_from_std(&fby, by);
    sm2_get_jacobian_z_field(&bz, &fbx, &fby);
    big_set(&rx, &big_zero);
    big_set(&ry, &big_zero);
    big_set(&rz, &big_zero);

    big_to_bytes(buf, &len, k);
    for (i = 0; i < len; i++) {
        byte = (unsigned long)buf[i];
        for (j = 0; j < 8; j++) {
            sm2_double_jacobian_field(&rx, &ry, &rz, &rx, &ry, &rz);
            if ((byte & 0x80) == 0x80) {
                sm2_add_jacobian_field(&rx, &ry, &rz, &rx, &ry, &rz, &fbx,
                                       &fby, &bz);
            }
            byte <<= 1;
        }
    }
    sm2_jacobian_to_affine_field(x3, y3, &rx, &ry, &rz);

    big_destroy(&fbx);
    big_destroy(&fby);
    big_destroy(&bz);
    big_destroy(&rx);
    big_destroy(&ry);
    big_destroy(&rz);
}

int sm2_infinit_p(const big_t* x, const big_t* y) {
    return big_cmp(x, &big_zero) == 0 || big_cmp(y, &big_zero) == 0;
}

int sm2_on_curve_p(const big_t* x, const big_t* y) {
    SM_STATIC big_t fx, fy;
    SM_STATIC big_t lhs, rhs, tmp1, tmp2;
    int r;

    big_init(&fx);
    big_init(&fy);
    big_init(&lhs);
    big_init(&rhs);
    big_init(&tmp1);
    big_init(&tmp2);

    sm2_fp_from_std(&fx, x);
    sm2_fp_from_std(&fy, y);

    sm2_fp_sqr(&lhs, &fy);
    sm2_fp_sqr(&tmp1, &fx);
    sm2_fp_mul(&rhs, &tmp1, &fx);

#ifndef USE_SLOW_BIGINT
    sm2_fp_mul(&tmp1, &sm2_a_field, &fx);
    sm2_fp_add(&tmp2, &rhs, &tmp1);
    sm2_fp_add(&rhs, &tmp2, &sm2_b_field);
#else
    sm2_fp_mul(&tmp1, &sm2_a, &fx);
    sm2_fp_add(&tmp2, &rhs, &tmp1);
    sm2_fp_add(&rhs, &tmp2, &sm2_b);
#endif

    r = (big_cmp(&lhs, &rhs) == 0);

    big_destroy(&fx);
    big_destroy(&fy);
    big_destroy(&lhs);
    big_destroy(&rhs);
    big_destroy(&tmp1);
    big_destroy(&tmp2);

    return r;
}
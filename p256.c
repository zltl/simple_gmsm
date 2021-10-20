#include "simple_gmsm/sm2.h"
#include "simple_gmsm/big.h"

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
}

void sm2_destroy(void) {
    big_destroy(&sm2_p);
    big_destroy(&sm2_a);
    big_destroy(&sm2_b);
    big_destroy(&sm2_n);
    big_destroy(&sm2_gx);
    big_destroy(&sm2_gy);
    big_destroy(&sm2_d_max);
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

// reverses the Jacobian transform.If the point is ∞ it returns 0, 0.
void sm2_jacobian_to_affine(big_t* xout, big_t* yout, const big_t* x,
                            const big_t* y, const big_t* z) {
    SM_STATIC big_t zinv, zinvsq, tmp;

    if (big_cmp(z, &big_zero) == 0) {
        big_set(xout, &big_zero);
        big_set(yout, &big_zero);
        return;
    }
    // x=X/Z^2
    // y=Y/Z^3
    big_init(&zinv);
    big_init(&zinvsq);
    big_init(&tmp);

    // big_hexp("z", z);
    // big_hexp("p", &sm2_p);
    big_inv(&zinv, z, &sm2_p);
    big_mul(&tmp, &zinv, &zinv);
    big_mod(&zinvsq, &tmp, &sm2_p);  // z^2 mod p
    big_mul(&tmp, x, &zinvsq);
    big_mod(xout, &tmp, &sm2_p);
    big_mul(&tmp, &zinvsq, &zinv);
    big_mod(&zinvsq, &tmp, &sm2_p);  // z^3 mod p
    big_mul(&tmp, y, &zinvsq);
    big_mod(yout, &tmp, &sm2_p);

    big_destroy(&zinv);
    big_destroy(&zinvsq);
    big_destroy(&tmp);
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
    SM_STATIC big_t z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v;
    SM_STATIC big_t tmp1, tmp2;
    int xequal = 0, yequal = 0;
    int cmpr;

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

    big_mul(&tmp1, z1, z1);
    big_mod(&z1z1, &tmp1, &sm2_p);  // Z1Z1 = Z1^2
    big_mul(&tmp1, z2, z2);
    big_mod(&z2z2, &tmp1, &sm2_p);  // Z2Z2 = Z2^2

    big_mul(&tmp1, x1, &z2z2);
    big_mod(&u1, &tmp1, &sm2_p);  // U1 = X1*Z2Z2
    big_mul(&tmp1, x2, &z1z1);
    big_mod(&u2, &tmp1, &sm2_p);  // U2 = X2*Z1Z1

    big_mul(&tmp1, y1, z2);
    big_mod(&s1, &tmp1, &sm2_p);
    big_mul(&tmp1, &s1, &z2z2);
    big_mod(&s1, &tmp1, &sm2_p);  // S1 = Y1*Z2*Z2Z2
    big_mul(&tmp1, y2, z1);
    big_mod(&s2, &tmp1, &sm2_p);
    big_mul(&tmp1, &s2, &z1z1);
    big_mod(&s2, &tmp1, &sm2_p);  // S2 = Y2*Z1*Z1Z1

    big_sub(&tmp1, &u2, &u1);  // H = U2-U1
    cmpr = big_cmp(&tmp1, &big_zero);
    xequal = (cmpr == 0);
    if (cmpr < 0) {
        big_add(&h, &tmp1, &sm2_p);
    } else {
        big_set(&h, &tmp1);
    }

    big_add(&tmp1, &h, &h);
    big_mod(&i, &tmp1, &sm2_p);
    big_mul(&tmp1, &i, &i);
    big_mod(&i, &tmp1, &sm2_p);  // I = (2*H)^2
    big_mul(&tmp1, &h, &i);
    big_mod(&j, &tmp1, &sm2_p);  // J = H*I

    big_sub(&tmp1, &s2, &s1);
    cmpr = big_cmp(&tmp1, &big_zero);
    yequal = (cmpr == 0);

    if (xequal && yequal) {
        sm2_double_jacobian(x3, y3, z3, x1, y1, z1);
        return;
    }

    if (cmpr < 0) {
        big_add(&r, &tmp1, &sm2_p);
    } else {
        big_set(&r, &tmp1);
    }
    big_add(&tmp1, &r, &r);
    big_mod(&r, &tmp1, &sm2_p);  // r = 2*(S2-S1)

    big_mul(&tmp1, &u1, &i);
    big_mod(&v, &tmp1, &sm2_p);  // V = U1*I

    // X3 = r^2-J-2*V
    big_mul(&tmp1, &r, &r);
    big_sub(x3, &tmp1, &j);
    big_add(&tmp1, &v, &v);
    big_sub(&tmp2, x3, &tmp1);
    while (big_cmp(&tmp2, &big_zero) < 0) {
        big_add(&tmp1, &tmp2, &sm2_p);
        big_set(&tmp2, &tmp1);
    }
    big_mod(x3, &tmp2, &sm2_p);

    // Y3 = r*(V-X3)-2*S1*J
    big_sub(&tmp1, &v, x3);
    if (big_cmp(&tmp1, &big_zero) < 0) {
        big_add(&tmp2, &tmp1, &sm2_p);
        big_set(&tmp1, &tmp2);
    }
    big_mul(&tmp2, &r, &tmp1);
    big_mod(y3, &tmp2, &sm2_p);  //  r*(V-X3)
    big_add(&tmp1, &s1, &s1);
    big_mod(&tmp2, &tmp1, &sm2_p);
    big_mul(&tmp1, &tmp2, &j);
    big_mod(&tmp2, &tmp1, &sm2_p);  // 2*S1*J
    big_sub(&tmp1, y3, &tmp2);
    if (big_cmp(&tmp1, &big_zero) < 0) {
        big_add(y3, &tmp1, &sm2_p);
    } else {
        big_set(y3, &tmp1);
    }
    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
    big_add(&tmp1, z1, z2);
    big_mod(&tmp2, &tmp1, &sm2_p);
    big_mul(&tmp1, &tmp2, &tmp2);
    big_mod(z3, &tmp1, &sm2_p);  // (Z1+Z2)^2
    big_sub(&tmp2, z3, &z1z1);
    big_sub(&tmp1, &tmp2, &z2z2);
    while (big_cmp(&tmp1, &big_zero) < 0) {
        big_add(&tmp2, &tmp1, &sm2_p);
        big_set(&tmp1, &tmp2);
    }
    big_mul(&tmp2, &tmp1, &h);
    big_mod(z3, &tmp2, &sm2_p);

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

/* point P1+P2 */
void sm2_add(big_t* x3, big_t* y3, big_t* x1, big_t* y1, big_t* x2, big_t* y2) {
    SM_STATIC big_t z1, z2, z3;
    SM_STATIC big_t tx, ty;
    big_init(&z1);
    big_init(&z2);
    big_init(&z3);
    big_init(&tx);
    big_init(&ty);

    sm2_get_jacobian_z(&z1, x1, y1);
    sm2_get_jacobian_z(&z2, x2, y2);

    sm2_add_jocabian(&tx, &ty, &z3, x1, y1, &z1, x2, y2, &z2);
    sm2_jacobian_to_affine(x3, y3, &tx, &ty, &z3);
    /*
    big_hexp("x1", x1);
    big_hexp("y1", y1);
    big_hexp("z1", &z1);
    big_hexp("x2", x2);
    big_hexp("y2", y2);
    big_hexp("z2", &z2);
    big_hexp("tx", &tx);
    big_hexp("ty", &ty);
    big_hexp("z3", &z3);
    big_hexp("x3", x1);
    big_hexp("y3", y1);
    */

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
    SM_STATIC big_t delta, gamma, beta, alpha, alpha2;
    SM_STATIC big_t tmp1, tmp2;
    SM_STATIC big_t eight, four;
    SM_STATIC unsigned char eight_buf[] = {8};
    SM_STATIC unsigned char four_buf[] = {4};

    big_init(&delta);
    big_init(&gamma);
    big_init(&beta);
    big_init(&alpha);
    big_init(&alpha2);
    big_init(&tmp1);
    big_init(&tmp2);
    big_init(&eight);
    big_init(&four);
    big_from_bytes(&eight, eight_buf, sizeof(eight_buf));
    big_from_bytes(&four, four_buf, sizeof(four_buf));

    big_mul(&tmp1, z1, z1);
    big_mod(&delta, &tmp1, &sm2_p);  // delta = Z1^2
    big_mul(&tmp1, y1, y1);
    big_mod(&gamma, &tmp1, &sm2_p);  // gamma = Y1^2
    big_mul(&tmp1, x1, &gamma);
    big_mod(&beta, &tmp1, &sm2_p);  // beta = X1*gamma
    // alpha = 3*(X1-delta)*(X1+delta)
    big_sub(&alpha, x1, &delta);
    while (big_cmp(&alpha, &big_zero) < 0) {
        big_add(&tmp1, &alpha, &sm2_p);
        big_set(&alpha, &tmp1);
    }
    big_add(&tmp1, x1, &delta);
    big_mod(&alpha2, &tmp1, &sm2_p);
    big_mul(&tmp1, &alpha, &alpha2);
    big_mod(&alpha, &tmp1, &sm2_p);
    big_mul(&tmp1, &alpha, &big_three);
    big_mod(&alpha, &tmp1, &sm2_p);

    // X3 = alpha^2-8*beta
    big_mul(&tmp1, &alpha, &alpha);
    big_mul(x3, &beta, &eight);
    big_sub(&tmp2, &tmp1, x3);
    while (big_cmp(&tmp2, &big_zero) < 0) {
        big_add(&tmp1, &tmp2, &sm2_p);
        big_set(&tmp2, &tmp1);
    }
    big_mod(x3, &tmp2, &sm2_p);

    // Z3 = (Y1+Z1)^2-gamma-delta
    big_add(&tmp1, y1, z1);
    big_mod(z3, &tmp1, &sm2_p);
    big_mul(&tmp1, z3, z3);
    big_sub(z3, &tmp1, &gamma);
    big_sub(&tmp1, z3, &delta);
    while (big_cmp(&tmp1, &big_zero) < 0) {
        big_add(&tmp2, &tmp1, &sm2_p);
        big_set(&tmp1, &tmp2);
    }
    big_mod(z3, &tmp1, &sm2_p);

    // Y3 = alpha*(4*beta-X3)-8*gamma^2
    big_mul(&tmp1, &beta, &four);
    big_sub(&tmp2, &tmp1, x3);
    while (big_cmp(&tmp2, &big_zero) < 0) {
        big_add(&tmp1, &tmp2, &sm2_p);
        big_set(&tmp2, &tmp1);
    }
    big_mod(&tmp1, &tmp2, &sm2_p);  // 4*beta-x3
    big_mul(&four, &alpha, &tmp1);
    big_mod(&tmp2, &four, &sm2_p);  // alpha * (4*beta-3)
    big_mul(&tmp1, &gamma, &gamma);
    big_mod(&delta, &tmp1, &sm2_p);
    big_mul(y3, &delta, &eight);
    big_mod(&gamma, y3, &sm2_p);  // 8*gamma^2
    big_sub(&tmp1, &tmp2, &gamma);
    while (big_cmp(&tmp1, &big_zero) < 0) {
        big_add(&tmp2, &tmp1, &sm2_p);
        big_set(&tmp1, &tmp2);
    }
    big_mod(y3, &tmp1, &sm2_p);

    big_destroy(&delta);
    big_destroy(&gamma);
    big_destroy(&beta);
    big_destroy(&alpha);
    big_destroy(&alpha2);
    big_destroy(&tmp1);
    big_destroy(&tmp2);
    big_destroy(&eight);
    big_destroy(&four);
}

void sm2_double(big_t* x3, big_t* y3, big_t* x1, big_t* y1) {
    SM_STATIC big_t z1, z3;
    SM_STATIC big_t tx, ty;
    big_init(&z1);
    big_init(&z3);
    big_init(&tx);
    big_init(&ty);

    sm2_get_jacobian_z(&z1, x1, y1);
    sm2_double_jacobian(&tx, &ty, &z3, x1, y1, &z1);
    sm2_jacobian_to_affine(x3, y3, &tx, &ty, &z3);

    big_destroy(&z1);
    big_destroy(&z3);
}

// (x3, y3) <- k * P(gx, by)
void sm2_scalar_mult(big_t* x3, big_t* y3, const big_t* bx, const big_t* by,
                     const big_t* k) {
    SM_STATIC big_t bz, z3;
    unsigned long i, j, byte;
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES];
    unsigned long len = sizeof(buf);

    big_init(&bz);
    big_init(&z3);
    big_set(x3, &big_zero);
    big_set(y3, &big_zero);
    big_set(&z3, &big_zero);
    sm2_get_jacobian_z(&bz, bx, by);

    big_to_bytes(buf, &len, k);
    for (i = 0; i < len; i++) {
        byte = (unsigned long)buf[i];
        for (j = 0; j < 8; j++) {
            sm2_double_jacobian(x3, y3, &z3, x3, y3, &z3);
            if ((byte & 0x80) == 0x80) {
                sm2_add_jocabian(x3, y3, &z3, x3, y3, &z3, bx, by, &bz);
            }
            byte <<= 1;
        }
    }
    sm2_jacobian_to_affine(x3, y3, x3, y3, &z3);
}

int sm2_infinit_p(const big_t* x, const big_t* y) {
    return big_cmp(x, &big_zero) == 0 || big_cmp(y, &big_zero) == 0;
}

int sm2_on_curve_p(const big_t* x, const big_t* y) {
    SM_STATIC big_t tmp1, tmp2, tmp3, tmp4;
    int r;

    big_init(&tmp1);
    big_init(&tmp2);
    big_init(&tmp3);
    big_init(&tmp4);

    big_mul(&tmp2, y, y);
    big_mod(&tmp1, &tmp2, &sm2_p);  // tmp1 <- y^2

    big_mul(&tmp3, x, x);
    big_mod(&tmp2, &tmp3, &sm2_p);  // tmp2 <- x^2
    big_mul(&tmp3, &tmp2, x);
    big_mod(&tmp2, &tmp3, &sm2_p);  // tmp2 <- x^3

    big_mul(&tmp4, &sm2_a, x);
    big_mod(&tmp3, &tmp4, &sm2_p);  // tmp3 <- ax

    big_add(&tmp4, &tmp2, &tmp3);
    big_add(&tmp3, &tmp4, &sm2_b);
    big_mod(&tmp2, &tmp3, &sm2_p);

    if (big_cmp(&tmp1, &tmp2) == 0)
        r = 1;
    else
        r = 0;

    big_destroy(&tmp1);
    big_destroy(&tmp2);
    big_destroy(&tmp3);
    big_destroy(&tmp4);

    return r;
}

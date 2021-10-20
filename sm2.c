#include "simple_gmsm/sm2.h"

#include <assert.h>

#include "endian.h"
#include "simple_gmsm/big.h"
#include "simple_gmsm/sm3.h"

#define SM2_MAX_BIG_BYTES 70

#define UNUSED __attribute__((unused))

extern unsigned char _p[32], _a[32], _b[32], _n[32], _gx[32], _gy[32];

static void __sm2_rmove_buf(unsigned char* buf, unsigned long datalen,
                            unsigned long destlen) {
    long i;

    if (datalen >= destlen) {
        return;
    }

    for (i = (long)datalen - 1; i >= 0; i--) {
        buf[destlen - (datalen - i)] = buf[i];
    }
    for (i = 0; i < (long)destlen - (long)datalen; i++) {
        buf[i] = 0;
    }
}

static int __sm2_buf_eq(unsigned char* a, unsigned long alen, unsigned char* b,
                        unsigned long blen) {
    unsigned long i;
    if (alen != blen) {
        return 0;
    }
    for (i = 0; i < alen; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

void sm2_gen_key(big_t* d, big_t* Px, big_t* Py) {
    big_t tmp1;
    big_init(&tmp1);

    big_rand(d, 256);
    // d in [1, n-2], that is (rand % (n-2))+1
    big_mod(&tmp1, d, &sm2_d_max);
    big_add(d, &tmp1, &big_one);

    sm2_scalar_mult(Px, Py, &sm2_gx, &sm2_gy, d);

    big_destroy(&tmp1);
}

// 密钥派生函数
void sm2_kdf(unsigned char* k, unsigned int klen, unsigned char* z,
             unsigned int zlen) {
    unsigned int i, j, ct = 1;
    SM_STATIC unsigned char sum[32];
    SM_STATIC unsigned char bufct[4];
    SM_STATIC sm3_context_t sm3_ctx;
    unsigned genlen = 0;

    for (i = 1; i <= (klen + 31) / 32; i++) {
        sm3_init(&sm3_ctx);
        sm3_update(&sm3_ctx, z, (unsigned long)zlen);
        PUTU32(ct, bufct, 0);
        sm3_update(&sm3_ctx, bufct, 4);
        sm3_finish(&sm3_ctx, sum);
        ct++;
        for (j = genlen; j < klen && j < genlen + 32; j++) {
            k[j] = sum[j - genlen];
        }
        genlen = j;
    }
}

// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
// ZB = H256(ENTLB || IDB || a || b || xG || yG || xB || yB)
// px, py 是A的公钥 (xA, yA)
// z 是32字节数组
void sm2_za(unsigned char* z, unsigned char* id, unsigned int idlen, big_t* px,
            big_t* py) {
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES];
    unsigned long buflen = sizeof(buf);
    unsigned int idlenbit = idlen * 8;
    SM_STATIC sm3_context_t sm3_ctx;
    sm3_init(&sm3_ctx);
    buf[0] = (unsigned char)((idlenbit >> 8) & 0xFF);
    buf[1] = (unsigned char)(idlenbit & 0xFF);
    sm3_update(&sm3_ctx, buf, 2);
    if (idlen > 0) {
        sm3_update(&sm3_ctx, id, idlen);
    }
    sm3_update(&sm3_ctx, _a, sizeof(_a));
    sm3_update(&sm3_ctx, _b, sizeof(_b));
    sm3_update(&sm3_ctx, _gx, sizeof(_gx));
    sm3_update(&sm3_ctx, _gy, sizeof(_gy));

    big_to_bytes(buf, &buflen, px);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    buflen = sizeof(buf);
    big_to_bytes(buf, &buflen, py);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    sm3_finish(&sm3_ctx, z);
}

static void __sm2_x_neg(big_t* xneg, big_t* x, unsigned char* buf,
                        unsigned long buflen, big_t* tmp1) {
    unsigned long i;
    big_to_bytes(buf, &buflen, x);
    for (i = 0; i < buflen && i < buflen - 16; i++) {
        buf[i] = 0;
    }
    if (buflen >= 16) {
        buf[buflen - 16] &= 0x7f;
    }
    big_from_bytes(tmp1, buf, buflen);
    big_add(xneg, &sm2_2w, tmp1);
    big_mod(tmp1, xneg, &sm2_p);
    big_set(xneg, tmp1);
}

static void __sm2_ke_opt_s(unsigned char* s, unsigned char* buf,
                           unsigned long xbuflen, unsigned char head,
                           big_t* uvx, big_t* uvy, unsigned char* za,
                           unsigned char* zb, big_t* rax, big_t* ray,
                           big_t* rbx, big_t* rby) {
    SM_STATIC sm3_context_t sm3_ctx;
    unsigned long buflen = xbuflen;

    sm3_init(&sm3_ctx);
    big_to_bytes(buf, &buflen, uvx);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    sm3_update(&sm3_ctx, za, 32);
    sm3_update(&sm3_ctx, zb, 32);
    buflen = xbuflen;
    big_to_bytes(buf, &buflen, rax);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    buflen = xbuflen;
    big_to_bytes(buf, &buflen, ray);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    buflen = xbuflen;
    big_to_bytes(buf, &buflen, rbx);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    buflen = xbuflen;
    big_to_bytes(buf, &buflen, rby);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    sm3_finish(&sm3_ctx, s);
    sm3_init(&sm3_ctx);
    buf[0] = head;
    sm3_update(&sm3_ctx, buf, 1);
    buflen = xbuflen;
    big_to_bytes(buf, &buflen, uvy);
    __sm2_rmove_buf(buf, buflen, 32);
    sm3_update(&sm3_ctx, buf, 32);
    sm3_update(&sm3_ctx, s, 32);
    sm3_finish(&sm3_ctx, s);
}

void sm2_ke_1(big_t* rax, big_t* ray, big_t* ra) { sm2_gen_key(ra, rax, ray); }

int sm2_ke_2(unsigned char* kb, unsigned long kblen, big_t* vx, big_t* vy,
             unsigned char* sb, big_t* rbx, big_t* rby, big_t* rb, big_t* db,
             big_t* rax, big_t* ray, big_t* pax, big_t* pay, unsigned char* za,
             unsigned char* zb, int opt) {
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES * 2];
    unsigned long buflen = sizeof(buf);
    unsigned long bufoffset;
    unsigned long i;
    SM_STATIC big_t tmp1, tmp2;
    SM_STATIC big_t x2neg, x1neg;
    SM_STATIC big_t tb;
    int ret = 1;

    big_init(&tmp1);
    big_init(&tmp2);
    big_init(&x2neg);
    big_init(&x1neg);
    big_init(&tb);

    __sm2_x_neg(&x2neg, rbx, buf, sizeof(buf), &tmp1);

    big_mul(&tmp1, &x2neg, rb);
    big_mod(&tb, &tmp1, &sm2_n);
    big_add(&tmp1, &tb, db);
    big_mod(&tb, &tmp1, &sm2_n);

    if (!sm2_on_curve_p(rax, ray)) {
        ret = 0;
        goto cleanup;  // 协商失败
    }
    __sm2_x_neg(&x1neg, rax, buf, sizeof(buf), &tmp1);

    sm2_scalar_mult(vx, vy, rax, ray, &x1neg);
    sm2_add(&tmp1, &tmp2, pax, pay, vx, vy);
    sm2_scalar_mult(vx, vy, &tmp1, &tmp2, &tb);
    if (sm2_infinit_p(vx, vy)) {
        ret = 0;
        goto cleanup;  // 协商失败
    }

    bufoffset = buflen;
    big_to_bytes(buf, &bufoffset, vx);
    __sm2_rmove_buf(buf, bufoffset, 32);
    bufoffset = 32;
    buflen = sizeof(buf) - bufoffset;
    big_to_bytes(buf + bufoffset, &buflen, vy);
    __sm2_rmove_buf(buf + bufoffset, buflen, 32);
    bufoffset += 32;
    for (i = 0; i < 32; i++) {
        buf[bufoffset++] = za[i];
    }
    for (i = 0; i < 32; i++) {
        buf[bufoffset++] = zb[i];
    }
    sm2_kdf(kb, (unsigned int)kblen, buf, bufoffset);

    if (opt && sb) {
        __sm2_ke_opt_s(sb, buf, sizeof(buf), 0x02, vx, vy, za, zb, rax, ray,
                       rbx, rby);
    }

cleanup:
    big_destroy(&tmp1);
    big_destroy(&tmp2);
    big_destroy(&x2neg);
    big_destroy(&x1neg);
    big_destroy(&tb);

    return ret;
}

// db is the private key of user B
// return true if ok, false else
int sm2_ke_3(unsigned char* ka, unsigned long kalen, unsigned char* sa,
             unsigned char* sb, big_t* rax, big_t* ray, big_t* ra, big_t* da,
             big_t* rbx, big_t* rby, big_t* pbx, big_t* pby, unsigned char* za,
             unsigned char* zb, int opt) {
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES * 2];
    unsigned long buflen = sizeof(buf);
    unsigned long bufoffset;
    SM_STATIC unsigned char sbs[32];
    unsigned long i;
    SM_STATIC big_t tmp1, tmp2;
    SM_STATIC big_t x2neg, x1neg;
    SM_STATIC big_t ta;
    SM_STATIC big_t ux, uy;
    int ret = 1;

    big_init(&tmp1);
    big_init(&tmp2);
    big_init(&x2neg);
    big_init(&x1neg);
    big_init(&ta);
    big_init(&ux);
    big_init(&uy);

    __sm2_x_neg(&x1neg, rax, buf, sizeof(buf), &tmp1);

    big_mul(&tmp1, &x1neg, ra);
    big_mod(&ta, &tmp1, &sm2_n);
    big_add(&tmp1, &ta, da);
    big_mod(&ta, &tmp1, &sm2_n);

    if (!sm2_on_curve_p(rbx, rby)) {
        ret = 0;
        goto cleanup;  // 协商失败
    }
    __sm2_x_neg(&x2neg, rbx, buf, sizeof(buf), &tmp1);

    sm2_scalar_mult(&ux, &uy, rbx, rby, &x2neg);
    sm2_add(&tmp1, &tmp2, pbx, pby, &ux, &uy);
    sm2_scalar_mult(&ux, &uy, &tmp1, &tmp2, &ta);
    if (sm2_infinit_p(&ux, &uy)) {
        ret = 0;
        goto cleanup;  // 协商失败
    }

    bufoffset = buflen;
    big_to_bytes(buf, &bufoffset, &ux);
    __sm2_rmove_buf(buf, bufoffset, 32);
    bufoffset = 32;
    buflen -= bufoffset;
    big_to_bytes(buf + bufoffset, &buflen, &uy);
    __sm2_rmove_buf(buf + bufoffset, buflen, 32);
    bufoffset += 32;
    for (i = 0; i < 32; i++) {
        buf[bufoffset++] = za[i];
    }
    for (i = 0; i < 32; i++) {
        buf[bufoffset++] = zb[i];
    }
    sm2_kdf(ka, (unsigned int)kalen, buf, bufoffset);

    if (opt && sa && sb) {
        // sb
        __sm2_ke_opt_s(sbs, buf, sizeof(buf), 0x02, &ux, &uy, za, zb, rax, ray,
                       rbx, rby);
        if (!__sm2_buf_eq(sbs, 32, sb, 32)) {
            ret = 0;
            goto cleanup;  // 协商失败
        }
        // sa
        __sm2_ke_opt_s(sa, buf, sizeof(buf), 0x03, &ux, &uy, za, zb, rax, ray,
                       rbx, rby);
    }

cleanup:
    big_destroy(&tmp1);
    big_destroy(&tmp2);
    big_destroy(&x2neg);
    big_destroy(&x1neg);
    big_destroy(&ta);
    big_destroy(&ux);
    big_destroy(&uy);

    return ret;
}

int sm2_ke_opt_4(unsigned char* sa, big_t* vx, big_t* vy, unsigned char* za,
                 unsigned char* zb, big_t* rax, big_t* ray, big_t* rbx,
                 big_t* rby) {
    SM_STATIC unsigned char sas[32];
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES * 4];
    __sm2_ke_opt_s(sas, buf, sizeof(buf), 0x03, vx, vy, za, zb, rax, ray, rbx,
                   rby);
    if (!__sm2_buf_eq(sas, 32, sa, 32)) {
        return 0;  // 协商失败
    }
    return 1;  // 协商成功
}

void sm2_sign_generate(unsigned char* sign /*64byte*/, unsigned char* m,
                       unsigned long mlen, unsigned char* za, const big_t* da) {
    SM_STATIC unsigned char summ[32];
    SM_STATIC sm3_context_t sm3_ctx;
    unsigned long olen;
    SM_STATIC big_t e, k, x1, y1, r, tmp1;
    big_init(&e);
    big_init(&k);
    big_init(&x1);
    big_init(&y1);
    big_init(&r);
    big_init(&tmp1);

    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, za, 32);
    sm3_update(&sm3_ctx, m, mlen);
    sm3_finish(&sm3_ctx, summ);

    big_from_bytes(&e, summ, 32);

A3:
    sm2_gen_key(&k, &x1, &y1);
    big_add(&tmp1, &e, &x1);
    big_mod(&r, &tmp1, &sm2_n);
    if (big_cmp(&r, &big_zero) == 0) {
        goto A3;
    }
    big_add(&tmp1, &r, &k);
    if (big_cmp(&tmp1, &sm2_n) == 0) {
        goto A3;
    }

    big_add(&tmp1, da, &big_one);
    big_inv(&x1, &tmp1, &sm2_n);
    big_mul(&tmp1, &r, da);
    big_mod(&y1, &tmp1, &sm2_n);
    big_sub(&tmp1, &k, &y1);
    if (big_cmp(&tmp1, &big_zero) < 0) {
        big_add(&y1, &tmp1, &sm2_n);
    } else {
        big_set(&y1, &tmp1);
    }
    big_mul(&tmp1, &x1, &y1);
    big_mod(&e, &tmp1, &sm2_n);

    olen = 32;
    big_to_bytes(sign, &olen, &r);
    __sm2_rmove_buf(sign, olen, 32);
    olen = 32;
    big_to_bytes(sign + 32, &olen, &e);
    __sm2_rmove_buf(sign + 32, olen, 32);

    big_destroy(&e);
    big_destroy(&k);
    big_destroy(&x1);
    big_destroy(&y1);
    big_destroy(&r);
    big_destroy(&tmp1);
}

int sm2_sign_verify(unsigned char* sign, unsigned char* m, unsigned long mlen,
                    unsigned char* za, const big_t* pax, const big_t* pay) {
    SM_STATIC big_t r, s, e, t, x, y, tmp1;
    SM_STATIC big_t sx, sy, tx, ty;

    int ret = 1;  // true, ok

    SM_STATIC unsigned char m2[32];
    SM_STATIC sm3_context_t sm3_ctx;

    big_init(&r);
    big_init(&s);
    big_init(&e);
    big_init(&t);
    big_init(&x);
    big_init(&y);
    big_init(&sx);
    big_init(&sy);
    big_init(&tx);
    big_init(&ty);

    big_init(&tmp1);

    big_from_bytes(&r, sign, 32);
    big_from_bytes(&s, sign + 32, 32);

    if (big_cmp(&r, &big_one) < 0) {
        ret = 0;  // false
        goto cleanup;
    }
    if (big_cmp(&r, &sm2_n) >= 0) {
        ret = 0;  // false
        goto cleanup;
    }

    if (big_cmp(&s, &big_one) < 0) {
        ret = 0;  // false
        goto cleanup;
    }
    if (big_cmp(&s, &sm2_n) >= 0) {
        ret = 0;  // false
        goto cleanup;
    }

    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, za, 32);
    sm3_update(&sm3_ctx, m, mlen);
    sm3_finish(&sm3_ctx, m2);
    big_from_bytes(&e, m2, 32);

    big_add(&tmp1, &r, &s);
    big_mod(&t, &tmp1, &sm2_n);

    if (big_cmp(&t, &big_zero) == 0) {
        ret = 0;
        goto cleanup;
    }

    sm2_scalar_mult(&sx, &sy, &sm2_gx, &sm2_gy, &s);
    sm2_scalar_mult(&tx, &ty, pax, pay, &t);
    sm2_add(&x, &y, &sx, &sy, &tx, &ty);

    big_add(&tmp1, &e, &x);
    big_mod(&tx, &tmp1, &sm2_n);
    if (big_cmp(&tx, &r) == 0) {
        ret = 1;
    } else {
        ret = 0;
    }

cleanup:
    big_destroy(&r);
    big_destroy(&s);
    big_destroy(&e);
    big_destroy(&t);
    big_destroy(&x);
    big_destroy(&y);
    big_destroy(&sx);
    big_destroy(&sy);
    big_destroy(&tx);
    big_destroy(&ty);
    big_destroy(&tmp1);
    return ret;
}

// csize >= mlen+32*2+1+32
int sm2_encrypt(unsigned char* c, unsigned long csize, unsigned char* m,
                unsigned long mlen, const big_t* px, const big_t* py) {
    big_t k;
    big_t x1, y1, x2, y2;
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES * 2];
    unsigned long coffset = 0;
    SM_STATIC sm3_context_t sm3_ctx;
    unsigned long i;
    int ok = 0;

    if (csize < mlen + 32 * 2 + 1 + 32) {
        return 0;
    }

    big_init(&k);
    big_init(&x1);
    big_init(&y1);
    big_init(&x2);
    big_init(&y2);

    while (!ok) {
        sm2_gen_key(&k, &x1, &y1);
        sm2_scalar_mult(&x2, &y2, px, py, &k);

        // C1 || C3 || C2

        // C1, size = 1+32+32, start at c[0]
        c[0] = 4;  // uncompress
        coffset = csize - 1;
        big_to_bytes(c + 1, &coffset, &x1);
        __sm2_rmove_buf(c + 1, coffset, 32);
        coffset = csize - 32 - 1;
        big_to_bytes(c + 1 + 32, &coffset, &y1);
        __sm2_rmove_buf(c + 1 + 32, coffset, 32);

        // x2 || y2
        coffset = 32;
        big_to_bytes(buf, &coffset, &x2);
        __sm2_rmove_buf(buf, coffset, 32);
        coffset = 32;
        big_to_bytes(buf + 32, &coffset, &y2);
        __sm2_rmove_buf(buf + 32, coffset, 32);

        // C3, size = 32, start at c[32+32+1]
        sm3_init(&sm3_ctx);
        sm3_update(&sm3_ctx, buf, 32);
        sm3_update(&sm3_ctx, m, mlen);
        sm3_update(&sm3_ctx, buf + 32, 32);
        sm3_finish(&sm3_ctx, c + 1 + 32 + 32);

        // C2, size = mlen, start at c[32+32+1+32]
        coffset = 1 + 32 * 2 + 32;
        sm2_kdf(c + coffset, mlen, buf, 64);
        for (i = 0; i < mlen; i++) {
            if (c[i + coffset] != 0) {
                ok = 1;
                break;
            }
        }
        if (!ok) {
            continue;
        }
        for (i = 0; i < mlen; i++) {
            c[coffset + i] ^= m[i];
        }
    }

    big_destroy(&k);
    big_destroy(&x1);
    big_destroy(&x2);
    big_destroy(&y1);
    big_destroy(&y2);

    return 1;
}

int sm2_decrypt(unsigned char* m, long msize, unsigned char* c, long clen,
                big_t* d) {
    big_t c1x, c1y, x2, y2;
    int ret = 1;
    unsigned long coffset, i;
    SM_STATIC unsigned char buf[SM2_MAX_BIG_BYTES * 2];
    sm3_context_t sm3_ctx;
    unsigned char sum[32];

    big_init(&c1x);
    big_init(&c1y);
    big_init(&x2);
    big_init(&y2);

    if (clen < 1 + 32 * 2 + 32) {
        ret = 0;
        goto cleanup;
    }

    if (msize < clen - 1 - 32 * 2 - 32) {
        ret = 0;
        goto cleanup;
    }

    if (c[0] != 4) {
        ret = 0;
        goto cleanup;
    }

    big_from_bytes(&c1x, c + 1, 32);
    big_from_bytes(&c1y, c + 32 + 1, 32);

    if (!sm2_on_curve_p(&c1x, &c1y)) {
        ret = 0;
        goto cleanup;
    }
    sm2_scalar_mult(&x2, &y2, &c1x, &c1y, d);

    // x2 || y2
    coffset = 32;
    big_to_bytes(buf, &coffset, &x2);
    __sm2_rmove_buf(buf, coffset, 32);
    coffset = 32;
    big_to_bytes(buf + 32, &coffset, &y2);
    __sm2_rmove_buf(buf + 32, coffset, 32);

    coffset = 1 + 32 * 2 + 32;
    sm2_kdf(m, clen - coffset, buf, 64);
    for (i = 0; i < clen - coffset; i++) {
        if (m[i] != 0) {
            ret = 1;
            break;
        }
    }
    if (!ret) {
        return ret;
    }

    for (i = 0; i < clen - coffset; i++) {
        m[i] ^= c[coffset + i];
    }

    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, buf, 32);
    sm3_update(&sm3_ctx, m, clen - coffset);
    sm3_update(&sm3_ctx, buf + 32, 32);
    sm3_finish(&sm3_ctx, sum);

    for (i = 0; i < 32; i++) {
        if (sum[i] != c[1 + 32 * 2 + i]) {
            ret = 0;
            goto cleanup;
        }
    }

cleanup:
    big_destroy(&c1x);
    big_destroy(&c1y);
    big_destroy(&x2);
    big_destroy(&y2);
    return ret;
}

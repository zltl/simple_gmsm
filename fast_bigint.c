/// @file fast_bigint.c
/// @brief 高性能大数运算实现。
/// @details 使用机器字长 (uint32_t/uint64_t) 进行运算，
/// 除法采用 Knuth Algorithm D，性能远优于 slow_dirty_bigint.c。

#include "simple_gmsm/fast_bigint.h"

#include <string.h>

/* ================================================================== */
/*  Internal types                                                     */
/* ================================================================== */

#if BIG_LIMB_BITS == 64
__extension__ typedef __int128 big_slimb2_t;
#else
typedef int64_t big_slimb2_t;
#endif

/* ================================================================== */
/*  PRNG (与 slow_dirty_bigint 保持兼容)                               */
/* ================================================================== */

static unsigned char __rand_fn(long sed) {
    static unsigned long k = 17;
    unsigned char r;
    k = (k + (unsigned long)sed * 233 + 233) % 100007;
    r = (unsigned char)((k + k * 233 + (unsigned long)sed * k) % 256);
    return r;
}

/* ================================================================== */
/*  Global constants                                                   */
/* ================================================================== */

big_t big_zero;
big_t big_one;
big_t big_two;
big_t big_three;

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static void __set_zero(big_t* a) {
    a->sign = 0;
    memset(a->limbs, 0, sizeof(a->limbs));
}

/// 返回有效 limb 数量 (最高非零 limb 的索引 + 1)
static int __limbs_len(const big_limb_t* a, int max) {
    int i;
    for (i = max - 1; i >= 0; i--) {
        if (a[i] != 0) return i + 1;
    }
    return 0;
}

/// 无符号 limb 数组比较
static int __limbs_cmp(const big_limb_t* a, const big_limb_t* b, int n) {
    int i;
    for (i = n - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/// 无符号加法: c = a + b, 返回进位
static big_limb_t __limbs_add(big_limb_t* c, const big_limb_t* a,
                              const big_limb_t* b, int n) {
    big_limb_t carry = 0;
    int i;
    for (i = 0; i < n; i++) {
        big_dlimb_t sum = (big_dlimb_t)a[i] + b[i] + carry;
        c[i] = (big_limb_t)sum;
        carry = (big_limb_t)(sum >> BIG_LIMB_BITS);
    }
    return carry;
}

/// 无符号减法: c = a - b, 返回借位 (0 或 1)
static big_limb_t __limbs_sub(big_limb_t* c, const big_limb_t* a,
                              const big_limb_t* b, int n) {
    big_limb_t borrow = 0;
    int i;
    for (i = 0; i < n; i++) {
        big_dlimb_t diff = (big_dlimb_t)a[i] - b[i] - borrow;
        c[i] = (big_limb_t)diff;
        borrow = (big_limb_t)((diff >> BIG_LIMB_BITS) != 0);
    }
    return borrow;
}

/// limb 前导零计数
static int __limb_clz(big_limb_t x) {
    if (x == 0) return BIG_LIMB_BITS;
#if BIG_LIMB_BITS == 64
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_clzll((unsigned long long)x);
#else
    int n = 0;
    if (x <= 0x00000000FFFFFFFFULL) { n += 32; x <<= 32; }
    if (x <= 0x0000FFFFFFFFFFFFULL) { n += 16; x <<= 16; }
    if (x <= 0x00FFFFFFFFFFFFFFULL) { n +=  8; x <<=  8; }
    if (x <= 0x0FFFFFFFFFFFFFFFULL) { n +=  4; x <<=  4; }
    if (x <= 0x3FFFFFFFFFFFFFFFULL) { n +=  2; x <<=  2; }
    if (x <= 0x7FFFFFFFFFFFFFFFULL) { n +=  1; }
    return n;
#endif
#else
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_clz((unsigned int)x);
#else
    int n = 0;
    if (x <= 0x0000FFFFU) { n += 16; x <<= 16; }
    if (x <= 0x00FFFFFFU) { n +=  8; x <<=  8; }
    if (x <= 0x0FFFFFFFU) { n +=  4; x <<=  4; }
    if (x <= 0x3FFFFFFFU) { n +=  2; x <<=  2; }
    if (x <= 0x7FFFFFFFU) { n +=  1; }
    return n;
#endif
#endif
}

/// 左移 s 位 (0 <= s < BIG_LIMB_BITS), 返回移出的高位
static big_limb_t __limbs_shl(big_limb_t* a, int n, int s) {
    big_limb_t carry = 0;
    int i;
    if (s == 0 || n == 0) return 0;
    for (i = 0; i < n; i++) {
        big_limb_t nc = a[i] >> (BIG_LIMB_BITS - s);
        a[i] = (a[i] << s) | carry;
        carry = nc;
    }
    return carry;
}

/// 右移 s 位 (0 <= s < BIG_LIMB_BITS)
static void __limbs_shr(big_limb_t* a, int n, int s) {
    int i;
    if (s == 0 || n == 0) return;
    for (i = 0; i < n - 1; i++) {
        a[i] = (a[i] >> s) | (a[i + 1] << (BIG_LIMB_BITS - s));
    }
    a[n - 1] >>= s;
}

/* ================================================================== */
/*  Knuth Algorithm D  (TAOCP Vol.2 §4.3.1)                           */
/* ================================================================== */

/// 内部除法: q = u[0..ulen-1] / v[0..vlen-1], r = 余数
/// q 和 r 必须已被 caller 清零
static void __big_divmod(big_limb_t* q, big_limb_t* r,
                         const big_limb_t* u, int ulen,
                         const big_limb_t* v, int vlen) {
    int i, j, cmp;

    if (vlen == 0 || ulen == 0) return;

    /* u < v: 商为 0, 余数为 u */
    if (ulen < vlen) {
        memcpy(r, u, (unsigned long)ulen * sizeof(big_limb_t));
        return;
    }
    if (ulen == vlen) {
        cmp = __limbs_cmp(u, v, ulen);
        if (cmp < 0) {
            memcpy(r, u, (unsigned long)ulen * sizeof(big_limb_t));
            return;
        }
        if (cmp == 0) {
            q[0] = 1;
            return;
        }
    }

    /* 单 limb 除数: 快速路径 */
    if (vlen == 1) {
        big_limb_t rem = 0;
        for (j = ulen - 1; j >= 0; j--) {
            big_dlimb_t tmp = ((big_dlimb_t)rem << BIG_LIMB_BITS) | u[j];
            q[j] = (big_limb_t)(tmp / v[0]);
            rem = (big_limb_t)(tmp % v[0]);
        }
        r[0] = rem;
        return;
    }

    /* Knuth Algorithm D (vlen >= 2) */
    {
        big_limb_t vn[BIG_LIMBS];
        big_limb_t un[BIG_LIMBS + 1];
        int s, m;

        /* D1: 正规化 - 使除数最高 limb 的最高位为 1 */
        s = __limb_clz(v[vlen - 1]);

        memset(vn, 0, sizeof(vn));
        memset(un, 0, sizeof(un));
        memcpy(vn, v, (unsigned long)vlen * sizeof(big_limb_t));
        memcpy(un, u, (unsigned long)ulen * sizeof(big_limb_t));

        if (s > 0) {
            __limbs_shl(vn, vlen, s);
            un[ulen] = __limbs_shl(un, ulen, s);
        }

        m = ulen - vlen;

        /* D2-D6: 主循环 */
        for (j = m; j >= 0; j--) {
            big_dlimb_t nn, qhat, rhat;
            big_slimb2_t k, t;

            /* D3: 试商 */
            nn = ((big_dlimb_t)un[j + vlen] << BIG_LIMB_BITS)
                 | un[j + vlen - 1];
            qhat = nn / vn[vlen - 1];
            rhat = nn % vn[vlen - 1];

            /* 精炼 qhat */
            for (;;) {
                if (qhat >= ((big_dlimb_t)1 << BIG_LIMB_BITS) ||
                    qhat * vn[vlen - 2] >
                        ((rhat << BIG_LIMB_BITS) + un[j + vlen - 2])) {
                    qhat--;
                    rhat += vn[vlen - 1];
                    if (rhat < ((big_dlimb_t)1 << BIG_LIMB_BITS))
                        continue;
                }
                break;
            }

            /* D4: 乘法并减 un[j..j+vlen] -= qhat * vn[0..vlen-1] */
            k = 0;
            for (i = 0; i < vlen; i++) {
                big_dlimb_t p =
                    (big_dlimb_t)(big_limb_t)qhat * vn[i];
                t = (big_slimb2_t)un[i + j] - k - (big_limb_t)p;
                un[i + j] = (big_limb_t)t;
                k = (big_slimb2_t)(p >> BIG_LIMB_BITS)
                    - (t >> BIG_LIMB_BITS);
            }
            t = (big_slimb2_t)un[j + vlen] - k;
            un[j + vlen] = (big_limb_t)t;

            q[j] = (big_limb_t)qhat;

            /* D5/D6: 若结果为负则回补 */
            if (t < 0) {
                big_limb_t c = 0;
                q[j]--;
                for (i = 0; i < vlen; i++) {
                    big_dlimb_t sum =
                        (big_dlimb_t)un[i + j] + vn[i] + c;
                    un[i + j] = (big_limb_t)sum;
                    c = (big_limb_t)(sum >> BIG_LIMB_BITS);
                }
                un[j + vlen] += c;
            }
        }

        /* D7: 反正规化余数 */
        memcpy(r, un, (unsigned long)vlen * sizeof(big_limb_t));
        if (s > 0) __limbs_shr(r, vlen, s);
    }
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

void big_prepare(void) {
    __set_zero(&big_zero);
    __set_zero(&big_one);
    __set_zero(&big_two);
    __set_zero(&big_three);
    big_one.sign = 1;
    big_two.sign = 1;
    big_three.sign = 1;
    big_one.limbs[0] = 1;
    big_two.limbs[0] = 2;
    big_three.limbs[0] = 3;
}

void big_finished(void) {}

void big_init(big_t* a) {
    a->sign = 0;
    {
        unsigned char* raw = (unsigned char*)a->limbs;
        int idx = __rand_fn(0) % (int)sizeof(a->limbs);
        __rand_fn((long)raw[idx]);
    }
}

void big_destroy(big_t* a) {
    {
        unsigned char* raw = (unsigned char*)a->limbs;
        int idx = __rand_fn(0) % (int)sizeof(a->limbs);
        __rand_fn((long)raw[idx]);
    }
    a->sign = 0;
}

void big_set(big_t* a, const big_t* b) {
    a->sign = b->sign;
    memcpy(a->limbs, b->limbs, sizeof(a->limbs));
}

void big_swap(big_t* a, big_t* b) {
    big_t t;
    big_set(&t, a);
    big_set(a, b);
    big_set(b, &t);
}

int big_cmp(const big_t* a, const big_t* b) {
    int r;
    if (a->sign != b->sign) {
        return a->sign - b->sign;
    }
    if (a->sign == 0) {
        return -1 * b->sign;
    }
    if (b->sign == 0) {
        return a->sign;
    }
    r = __limbs_cmp(a->limbs, b->limbs, BIG_LIMBS);
    if (a->sign < 0) {
        return -1 * r;
    }
    return r;
}

void big_add(big_t* c, const big_t* a, const big_t* b) {
    int cmp;

    if (a->sign == 0) { big_set(c, b); return; }
    if (b->sign == 0) { big_set(c, a); return; }

    /* 同号: 绝对值相加 */
    if (a->sign == b->sign) {
        __limbs_add(c->limbs, a->limbs, b->limbs, BIG_LIMBS);
        c->sign = a->sign;
        return;
    }

    /* 异号: |大| - |小| */
    cmp = __limbs_cmp(a->limbs, b->limbs, BIG_LIMBS);
    if (cmp == 0) {
        __set_zero(c);
        return;
    }
    if (cmp < 0) {
        __limbs_sub(c->limbs, b->limbs, a->limbs, BIG_LIMBS);
    } else {
        __limbs_sub(c->limbs, a->limbs, b->limbs, BIG_LIMBS);
    }
    c->sign = a->sign * cmp;
}

void big_sub(big_t* c, const big_t* a, const big_t* b) {
    int cmp;

    if (a->sign == 0) {
        big_set(c, b);
        c->sign = -b->sign;
        return;
    }
    if (b->sign == 0) {
        big_set(c, a);
        return;
    }

    /* 异号: 绝对值相加 */
    if (a->sign != b->sign) {
        __limbs_add(c->limbs, a->limbs, b->limbs, BIG_LIMBS);
        c->sign = (a->sign > 0) ? 1 : -1;
        return;
    }

    /* 同号: |大| - |小|, 确定结果符号 */
    cmp = __limbs_cmp(a->limbs, b->limbs, BIG_LIMBS);
    if (cmp == 0) {
        __set_zero(c);
        return;
    }
    if (cmp > 0) {
        __limbs_sub(c->limbs, a->limbs, b->limbs, BIG_LIMBS);
        c->sign = (a->sign == -1) ? -1 : 1;
    } else {
        __limbs_sub(c->limbs, b->limbs, a->limbs, BIG_LIMBS);
        c->sign = (a->sign == -1) ? 1 : -1;
    }
}

void big_mul(big_t* c, const big_t* a, const big_t* b) {
    big_limb_t tmp[2 * BIG_LIMBS];
    int i, j, alen, blen;

    if (a->sign == 0 || b->sign == 0) {
        __set_zero(c);
        return;
    }

    alen = __limbs_len(a->limbs, BIG_LIMBS);
    blen = __limbs_len(b->limbs, BIG_LIMBS);

    memset(tmp, 0, sizeof(tmp));

    for (i = 0; i < alen; i++) {
        big_limb_t carry = 0;
        for (j = 0; j < blen; j++) {
            big_dlimb_t prod = (big_dlimb_t)a->limbs[i] * b->limbs[j]
                               + tmp[i + j] + carry;
            tmp[i + j] = (big_limb_t)prod;
            carry = (big_limb_t)(prod >> BIG_LIMB_BITS);
        }
        tmp[i + blen] = carry;
    }

    c->sign = a->sign * b->sign;
    memcpy(c->limbs, tmp, sizeof(c->limbs));
}

void big_div(big_t* c, const big_t* a, const big_t* b) {
    big_t r;
    big_limb_t ql[BIG_LIMBS];
    big_limb_t al[BIG_LIMBS];
    int ulen, vlen;

    if (a->sign == 0) { __set_zero(c); return; }

    /* 拷贝 a 以支持 c == a 的别名情况 */
    memcpy(al, a->limbs, sizeof(al));
    ulen = __limbs_len(al, BIG_LIMBS);
    vlen = __limbs_len(b->limbs, BIG_LIMBS);

    memset(ql, 0, sizeof(ql));
    memset(r.limbs, 0, sizeof(r.limbs));

    __big_divmod(ql, r.limbs, al, ulen, b->limbs, vlen);

    memcpy(c->limbs, ql, sizeof(c->limbs));
    c->sign = a->sign * b->sign;
    if (__limbs_len(c->limbs, BIG_LIMBS) == 0) c->sign = 0;
}

void big_mod(big_t* c, const big_t* a, const big_t* b) {
    big_limb_t q[BIG_LIMBS];
    big_limb_t rl[BIG_LIMBS];
    big_limb_t al[BIG_LIMBS];
    int ulen, vlen;

    if (a->sign == 0) { __set_zero(c); return; }

    /* 拷贝 a 以支持 c == a 的别名情况 */
    memcpy(al, a->limbs, sizeof(al));
    ulen = __limbs_len(al, BIG_LIMBS);
    vlen = __limbs_len(b->limbs, BIG_LIMBS);

    memset(q, 0, sizeof(q));
    memset(rl, 0, sizeof(rl));

    __big_divmod(q, rl, al, ulen, b->limbs, vlen);

    memcpy(c->limbs, rl, sizeof(c->limbs));
    c->sign = (__limbs_len(c->limbs, BIG_LIMBS) > 0) ? 1 : 0;
}

int big_inv(big_t* x, const big_t* _a, const big_t* m) {
    big_t m0, tty, ty, t, y, a, q;

    big_init(&m0);
    big_init(&tty);
    big_init(&ty);
    big_init(&t);
    big_init(&a);
    big_init(&q);

    big_set(&m0, m);
    big_set(&ty, &big_zero);
    big_set(&y, &big_zero);
    big_set(x, &big_one);
    big_set(&a, _a);
    if (big_cmp(&m0, &big_one) == 0) {
        return 0;
    }

    while (big_cmp(&a, &big_one) > 0) {
        if (big_cmp(&m0, &big_zero) == 0) {
            return 0;
        }
        big_div(&q, &a, &m0);
        big_set(&t, &m0);
        big_mod(&m0, &a, &t);
        big_set(&a, &t);
        big_set(&t, &y);
        big_mul(&tty, &q, &y);
        big_mod(&ty, &tty, m);
        big_sub(&tty, x, &ty);
        if (big_cmp(&tty, &big_zero) < 0) {
            big_add(&y, &tty, m);
        } else {
            big_set(&y, &tty);
        }
        big_set(x, &t);
    }

    big_destroy(&m0);
    big_destroy(&tty);
    big_destroy(&ty);
    big_destroy(&t);
    big_destroy(&a);
    big_destroy(&q);

    return 1;
}

void big_from_bytes(big_t* a, unsigned char* buf, long buf_len) {
    long i;
    long max_bytes = (long)(BIG_LIMBS * BIG_LIMB_BYTES);

    memset(a->limbs, 0, sizeof(a->limbs));
    a->sign = 1;

    /* buf 是大端序: buf[0]=MSB, buf[buf_len-1]=LSB */
    /* limbs 是小端序: limbs[0]=最低有效字 */
    for (i = 0; i < buf_len && i < max_bytes; i++) {
        int limb_idx = (int)(i / BIG_LIMB_BYTES);
        int bit_shift = (int)((i % BIG_LIMB_BYTES) * 8);
        a->limbs[limb_idx] |=
            (big_limb_t)buf[buf_len - 1 - i] << bit_shift;
    }
}

void big_to_bytes(unsigned char* buf, unsigned long* buf_len,
                  const big_t* a) {
    int total_bytes = BIG_LIMBS * BIG_LIMB_BYTES;
    unsigned char temp[BIG_LIMBS * BIG_LIMB_BYTES];
    int i, start;
    unsigned long j, out_len;

    /* limbs 转大端序字节 */
    for (i = 0; i < total_bytes; i++) {
        int limb_idx = i / BIG_LIMB_BYTES;
        int byte_idx = i % BIG_LIMB_BYTES;
        temp[total_bytes - 1 - i] =
            (unsigned char)(a->limbs[limb_idx] >> (byte_idx * 8));
    }

    /* 跳过前导零 */
    start = 0;
    while (start < total_bytes && temp[start] == 0) start++;

    out_len = (unsigned long)(total_bytes - start);
    if (out_len > *buf_len) out_len = *buf_len;

    for (j = 0; j < out_len; j++) {
        buf[j] = temp[(unsigned long)start + j];
    }
    *buf_len = out_len;
}

void big_rand(big_t* a, unsigned long n) {
    unsigned long i;
    unsigned long max_bytes = BIG_LIMBS * BIG_LIMB_BYTES;
    unsigned char* raw;

    __set_zero(a);
    a->sign = 1;

    raw = (unsigned char*)a->limbs;
    for (i = 0; i < n && i < max_bytes; i++) {
        raw[i] = __rand_fn((long)(uintptr_t)a->limbs);
    }
}

int big_odd_p(big_t* a) {
    return (int)(a->limbs[0] & 1);
}

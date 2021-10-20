#include "simple_gmsm/slow_dirty_bigint.h"

/// 生成随机字节
/// 反复调用可以增加随机数
// TODO: 设置更合理的随机数生成器
static unsigned char __rand_fn(long sed) {
    static unsigned long k = 17;
    unsigned char r;
    k = (k + sed * 233 + 233) % 100007;
    r = (k + k * 233 + sed * k) % 256;
    return r;
}

big_t big_zero;
big_t big_one;
big_t big_two;
big_t big_three;

void big_init(big_t* a) {
    a->sign = 0;
    __rand_fn((long)a->num[__rand_fn(0) % sizeof(a->num)]);
}

void big_destroy(big_t* a) {
    a->sign = 0;
    __rand_fn((long)a->num[__rand_fn(0) % sizeof(a->num)]);
}

/// 大数赋值为 0
static void __big_set_zero(big_t* a) {
    unsigned long i;
    a->sign = 0;
    for (i = 0; i < sizeof(a->num); i++) {
        a->num[i] = 0;
    }
}

/// 初始化 big_zero, big_one, big_two, big_three
void big_prepare(void) {
    unsigned long xlen;
    __big_set_zero(&big_zero);
    __big_set_zero(&big_one);
    __big_set_zero(&big_two);
    __big_set_zero(&big_three);
    big_one.sign = 1;
    big_two.sign = 1;
    big_three.sign = 1;
    xlen = sizeof(big_zero.num);
    big_one.num[xlen - 1] = 1;
    big_two.num[xlen - 1] = 2;
    big_three.num[xlen - 1] = 3;
}

void big_finished(void) {}

/// 按照字节比较大小, 忽略符号。
/// 注意 a[0] 是高位, a[n] 是低位。
static int __big_cmp_digit(const big_t* a, const big_t* b) {
    unsigned long i;
    for (i = 0; i < sizeof(a->num); i++) {
        int c = (int)a->num[i] - (int)b->num[i];
        if (c != 0) {
            return c > 0 ? 1 : -1;
        }
    }
    return 0;
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

    r = __big_cmp_digit(a, b);
    if (a->sign < 0) {
        return -1 * r;
    }
    return r;
}

/// 按照字节相加， 忽略符号
static void __big_add_digit(big_t* c, const big_t* a, const big_t* b) {
    long i;
    int cc = 0;
    int t = 0;
    for (i = sizeof(c->num) - 1; i >= 0; i--) {
        t = a->num[i] + b->num[i] + cc;
        c->num[i] = t % 256;
        cc = t / 256;
    }
}

/// 按照字节相减，忽略符号
static void __big_sub_digit(big_t* c, const big_t* a, const big_t* b) {
    long i, cc = 0, t = 0;
    for (i = sizeof(c->num) - 1; i >= 0; i--) {
        t = a->num[i] - b->num[i] - cc;
        if (t < 0) {
            t += 256;
            cc = 1;
        } else {
            cc = 0;
        }
        c->num[i] = t;
    }
}

// c = a + b
void big_add(big_t* c, const big_t* a, const big_t* b) {
    int cmpdigitab;
    if (a->sign == 0) {
        big_set(c, b);
        return;
    }
    if (b->sign == 0) {
        big_set(c, a);
        return;
    }

    if (a->sign == b->sign) {
        __big_add_digit(c, a, b);
        c->sign = a->sign;
        return;
    }

    cmpdigitab = __big_cmp_digit(a, b);
    if (cmpdigitab == 0) {
        c->sign = 0;
        return;
    }

    if (cmpdigitab < 0) {
        __big_sub_digit(c, b, a);
    } else {
        __big_sub_digit(c, a, b);
    }

    c->sign = a->sign * cmpdigitab;
}

// c = a - b
void big_sub(big_t* c, const big_t* a, const big_t* b) {
    int cmpdigitab;
    if (a->sign == 0) {
        big_set(c, b);
        c->sign = -b->sign;
        return;
    }
    if (b->sign == 0) {
        big_set(c, a);
        return;
    }

    if (a->sign != b->sign) {
        __big_add_digit(c, a, b);
        if (a->sign > 0)  // a - (-b)
            c->sign = 1;
        else  // (-a) - b
            c->sign = -1;

        return;
    }

    cmpdigitab = __big_cmp_digit(a, b);
    if (cmpdigitab == 0) {
        big_set(c, &big_zero);
        return;
    }

    if (cmpdigitab > 0) {
        __big_sub_digit(c, a, b);
        if (a->sign == -1)  // (-a) - (-b) --> -a + b , a > b
            c->sign = -1;
        else  // a - b, a > b
            c->sign = 1;
        return;
    }
    __big_sub_digit(c, b, a);
    if (a->sign == -1)  // -a - (-b) --> -a + b, b > a
        c->sign = 1;
    else  // a  - b, b > a
        c->sign = -1;
    return;
}

// c = a * b
void big_mul(big_t* c, const big_t* a, const big_t* b) {
    unsigned long len;

    unsigned long i, j, t;
    unsigned long r;

    if (a->sign == 0 || b->sign == 0) {
        c->sign = 0;
        return;
    }
    len = sizeof(a->num);

    __big_set_zero(c);
    c->sign = a->sign * b->sign;

    for (i = 0; i < sizeof(a->num) / 2; i++) {
        r = 0;
        for (j = 0; j < sizeof(a->num) / 2; j++) {
            r += (long)a->num[len - i - 1] * (long)b->num[len - j - 1] +
                 (long)c->num[len - i - j - 1];
            c->num[len - i - j - 1] = r % 256;
            r = r / 256;
        }
        t = len - i - j - 1;
        while (t <= sizeof(a->num) && r > 0) {
            r += c->num[t];
            c->num[t++] = r % 256;
            r /= 256;
        }
    }
}

/// 正整数乘法
void __big_mul_digit(big_t* c, const big_t* a, const unsigned char d) {
    long i;
    long r = 0;
    long len = sizeof(a->num);

    __big_set_zero(c);
    for (i = len - 1; i >= 0; i--) {
        r += (long)a->num[i] * (long)d;
        c->num[i] = r % 256;
        r = r / 256;
    }
}

/// 左移8位
static void __big_lshift_8x(big_t* a, int n) {
    unsigned long i;
    for (i = 0; i < sizeof(a->num) - n; i++) a->num[i] = a->num[i + n];
    for (; i < sizeof(a->num); i++) a->num[i] = 0;
}

/// 右移8位
static void __big_rshift_8x(big_t* a, int n) {
    long i;
    if (n < 0) {
        return;
    }
    for (i = sizeof(a->num) - 1; i - n >= 0 && i > 0; i--) {
        a->num[i] = a->num[i - n];
    }
    for (; i >= 0; i--) {
        a->num[i] = 0;
    }
}

/**
 *  c = a / b ... r
     i ->...
div  0 1 2 8 ->  c {j, j, j...}
17 /---------
  /  2 1 7 7  -> r
     1 7 0 0  -> sub
    ---------
     0 4 7 7  -> next r
     0 3 4 0
    ---------
     0 1 3 7
     0 1 3 6
    ---------
     0 0 0 1  --> r
*/
static void __big_div_r(big_t* c, big_t* r, const big_t* a, const big_t* b) {
    long i, j, d;
    big_t sub, div, rt;
    int shift;
    int divlen;
    long xlen = sizeof(a->num);
    long jl = 0, jr = 256, m = 0;
    int rmd = 0;

    /* EXCEPTION
    if (b->sign) {
        c->sign = 1 / 0;
    }
    */

    if (a->sign == 0) {
        r->sign = 0;
        return;
    }

    big_init(&sub);
    big_init(&div);
    big_init(&rt);
    rt.sign = 1;
    __big_set_zero(c);

    big_set(&div, b);
    big_set(r, a);

    c->sign = a->sign * b->sign;

    // skip zero
    for (i = 0; i < xlen && div.num[i] == 0; i++)
        ;
    for (j = 0; j < xlen && a->num[j] == 0; j++)
        ;
    shift = i - j;
    if (shift < 0) {
        return;
    }
    divlen = xlen - i;
    __big_lshift_8x(&div, shift);

    for (i = j; i + divlen - 1 < xlen; i++) {
        if (__big_cmp_digit(r, b) < 0) {
            break;
        }

        // get upper bound of [0, 255]
        jl = 0, jr = 256, m = 0;
        while (jl < jr) {
            m = (jl + jr) / 2;
            __big_mul_digit(&sub, &div, m);
            rmd = __big_cmp_digit(&sub, r);
            if (rmd <= 0) {
                jl = m + 1;
            } else {
                jr = m;
            }
        }
        d = jl - 1;
        __big_mul_digit(&sub, &div, d);
        sub.sign = 1;

        __big_sub_digit(&rt, r, &sub);
        big_set(r, &rt);
        c->num[i + divlen - 1] = d;
        __big_rshift_8x(&div, 1);
    }
    for (i = xlen - 1; i >= 0; i++) {
        if (r->num[i]) {
            r->sign = 1;
            break;
        }
    }
}

void big_div(big_t* c, const big_t* a, const big_t* b) {
    big_t r;
    __big_div_r(c, &r, a, b);
}

// c = a % b
void big_mod(big_t* c, const big_t* a, const big_t* b) {
    big_t r;
    __big_div_r(&r, c, a, b);
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
        return 0;  // no inv
    }

    while (big_cmp(&a, &big_one) > 0) {
        if (big_cmp(&m0, &big_zero) == 0) {
            return 0;  // no inv
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

    return 1;  // ok
}

// import / export big number.
// buf must be big endian.
void big_from_bytes(big_t* a, unsigned char* buf, long buf_len) {
    long i;
    long xlen = sizeof(a->num);
    for (i = 0; i < buf_len && i < xlen; i++) {
        a->num[xlen - buf_len + i] = buf[i];
    }

    for (i = 0; i < xlen - buf_len; i++) {
        a->num[i] = 0;
    }
    a->sign = 1;
}
void big_to_bytes(unsigned char* buf, unsigned long* buf_len, const big_t* a) {
    unsigned long i, j;
    unsigned long xlen = sizeof(a->num);
    for (i = 0; i < xlen && a->num[i] == 0; i++)
        ;

    for (j = 0; j + i < xlen && j < *buf_len; j++) {
        buf[j] = a->num[i + j];
    }
    *buf_len = j;
}

// a <- b
void big_set(big_t* a, const big_t* b) {
    unsigned long i;
    a->sign = b->sign;
    for (i = 0; i < sizeof(a->num); i++) {
        a->num[i] = b->num[i];
    }
}
// swap
void big_swap(big_t* a, big_t* b) {
    big_t t;
    big_set(&t, a);
    big_set(a, b);
    big_set(b, &t);
}

// generate random number range 0 to 2^n-1
void big_rand(big_t* a, unsigned long n) {
    unsigned long i;
    unsigned long xlen = sizeof(a->num);
    __big_set_zero(a);
    a->sign = 1;

    for (i = 0; i < n && i < xlen; i++) {
        a->num[xlen - i - 1] = __rand_fn((long)a->num);
    }
}

// determin whether a is odd.
int big_odd_p(big_t* a) { return (a->num[sizeof(a->num) - 1] & 0x01); }

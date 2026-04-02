/** @file example_sm2.c
 *  @brief SM2 椭圆曲线密码示例：密钥生成、签名验签、加密解密
 *  @example example_sm2.c
 */
#include <stdio.h>
#include <string.h>
#include "simple_gmsm/slow_dirty_bigint.h"
#include "simple_gmsm/sm2.h"

static void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s", label);
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    /* 初始化大数库和 SM2 参数 */
    big_prepare();
    sm2_init();

    /* ========== 密钥生成 ========== */
    printf("=== SM2 密钥生成 ===\n");
    big_t d, px, py;
    big_init(&d);
    big_init(&px);
    big_init(&py);
    sm2_gen_key(&d, &px, &py);
    printf("✓ 已生成 SM2 密钥对\n\n");

    /* ========== 签名与验签 ========== */
    printf("=== SM2 签名与验签 ===\n");
    {
        unsigned char id[] = "1234567812345678";  /* 默认用户标识 */
        unsigned char za[32];
        sm2_za(za, id, 16, &px, &py);

        unsigned char msg[] = "hello SM2 signature";
        unsigned char sig[64];
        sm2_sign_generate(sig, msg, strlen((const char *)msg), za, &d);
        print_hex("签名: ", sig, 64);

        int ok = sm2_sign_verify(sig, msg, strlen((const char *)msg), za, &px, &py);
        if (!ok) { fprintf(stderr, "签名验证失败!\n"); goto fail; }
        printf("✓ 签名验证通过\n\n");
    }

    /* ========== 加密与解密 ========== */
    printf("=== SM2 加密与解密 ===\n");
    {
        unsigned char plain[] = "SM2 public key encryption test";
        unsigned long plen = strlen((const char *)plain);
        /* 密文长度 = 04 + 坐标(32*2) + MAC(32) + 明文长度 */
        unsigned long clen = 1 + 32 * 2 + 32 + plen;
        unsigned char cipher[256], dec[256];

        int r = sm2_encrypt(cipher, clen, plain, plen, &px, &py);
        if (!r) { fprintf(stderr, "加密失败!\n"); goto fail; }
        print_hex("密文(前32字节): ", cipher, 32);

        r = sm2_decrypt(dec, (long)plen, cipher, (long)clen, &d);
        if (!r) { fprintf(stderr, "解密失败!\n"); goto fail; }

        if (memcmp(dec, plain, plen) != 0) {
            fprintf(stderr, "解密结果不匹配!\n"); goto fail;
        }
        printf("✓ 加解密正确\n");
    }

    big_destroy(&d);
    big_destroy(&px);
    big_destroy(&py);
    sm2_destroy();
    return 0;

fail:
    big_destroy(&d);
    big_destroy(&px);
    big_destroy(&py);
    sm2_destroy();
    return 1;
}

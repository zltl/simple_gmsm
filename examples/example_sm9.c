/** @file example_sm9.c
 *  @brief SM9 标识密码示例：主密钥生成、用户密钥提取、加密解密
 *  @example example_sm9.c
 *
 *  注意: 使用 slow_dirty_bigint 后端时，SM9 运算非常缓慢，
 *  加密+解密可能需要约 2 分钟，请耐心等待。
 */
#include <stdio.h>
#include <string.h>
#include "simple_gmsm/slow_dirty_bigint.h"
#include "simple_gmsm/sm9.h"

static void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s", label);
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    /* 初始化大数库和 SM9 参数 */
    big_prepare();
    sm9_init();

    printf("=== SM9 标识加密示例 ===\n");
    printf("(使用 slow_dirty_bigint 后端，运算较慢，请耐心等待...)\n\n");

    /* 生成加密主密钥 */
    sm9_enc_master_key_t mk;
    memset(&mk, 0, sizeof(mk));
    sm9_enc_master_keygen(&mk);
    printf("✓ 已生成加密主密钥\n");

    /* 为用户提取私钥 */
    const unsigned char *id = (const unsigned char *)"alice@example.com";
    unsigned long idlen = strlen((const char *)id);
    sm9_enc_user_key_t uk;
    memset(&uk, 0, sizeof(uk));
    int r = sm9_enc_user_key_extract(&uk, &mk, id, idlen);
    if (!r) { fprintf(stderr, "用户密钥提取失败!\n"); goto fail; }
    printf("✓ 已为 \"%s\" 提取用户私钥\n\n", (const char *)id);

    /* 加密 */
    unsigned char msg[] = "Hello SM9!";
    unsigned long msglen = strlen((const char *)msg);
    unsigned char ct[256];
    unsigned long ctlen = 0;

    printf("正在加密 (可能需要较长时间) ...\n");
    r = sm9_encrypt(ct, sizeof(ct), &ctlen, msg, msglen, id, idlen, &mk);
    if (!r) { fprintf(stderr, "加密失败!\n"); goto fail; }
    printf("✓ 加密完成, 密文长度 = %lu\n", ctlen);
    print_hex("密文(前32字节): ", ct, ctlen < 32 ? ctlen : 32);

    /* 解密 */
    unsigned char dec[256];
    unsigned long declen = 0;
    printf("\n正在解密 ...\n");
    r = sm9_decrypt(dec, sizeof(dec), &declen, ct, ctlen, id, idlen, &uk);
    if (!r) { fprintf(stderr, "解密失败!\n"); goto fail; }

    if (declen != msglen || memcmp(dec, msg, msglen) != 0) {
        fprintf(stderr, "解密结果不匹配!\n"); goto fail;
    }
    printf("✓ 解密成功: %.*s\n", (int)declen, dec);

    sm9_destroy();
    return 0;

fail:
    sm9_destroy();
    return 1;
}

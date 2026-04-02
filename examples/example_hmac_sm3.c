/** @file example_hmac_sm3.c
 *  @brief HMAC-SM3 消息认证码示例：演示一次性和流式 HMAC
 *  @example example_hmac_sm3.c
 */
#include <stdio.h>
#include <string.h>
#include "simple_gmsm/hmac_sm3.h"

static void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s", label);
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    const unsigned char key[] = "sm3-hmac-secret-key";
    unsigned long keylen = strlen((const char *)key);
    const unsigned char msg[] = "hello, HMAC-SM3!";
    unsigned long msglen = strlen((const char *)msg);
    unsigned char mac1[32], mac2[32];

    /* === 一次性 HMAC === */
    hmac_sm3(key, keylen, msg, msglen, mac1);
    print_hex("一次性 HMAC: ", mac1, 32);

    /* === 流式 HMAC === */
    hmac_sm3_context_t ctx;
    hmac_sm3_init(&ctx, key, keylen);
    /* 分两段输入 */
    hmac_sm3_update(&ctx, msg, 8);
    hmac_sm3_update(&ctx, msg + 8, msglen - 8);
    hmac_sm3_finish(&ctx, mac2);
    print_hex("流式 HMAC:   ", mac2, 32);

    /* 两种方式结果应相同 */
    if (memcmp(mac1, mac2, 32) != 0) {
        fprintf(stderr, "错误: HMAC 结果不一致!\n");
        return 1;
    }
    printf("✓ 两种方式结果一致\n");
    return 0;
}

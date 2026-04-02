/** @file example_sm3.c
 *  @brief SM3 哈希算法示例：演示一次性哈希和流式哈希
 *  @example example_sm3.c
 */
#include <stdio.h>
#include <string.h>
#include "simple_gmsm/sm3.h"

/* 以十六进制打印字节数组 */
static void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s", label);
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    const unsigned char msg[] = "hello, SM3!";
    unsigned long msglen = strlen((const char *)msg);
    unsigned char hash1[32], hash2[32];

    /* === 一次性哈希 === */
    sm3(msg, msglen, hash1);
    print_hex("一次性哈希: ", hash1, 32);

    /* === 流式/增量哈希 === */
    sm3_context_t ctx;
    sm3_init(&ctx);
    /* 分两段输入同一消息 */
    sm3_update(&ctx, msg, 6);
    sm3_update(&ctx, msg + 6, msglen - 6);
    sm3_finish(&ctx, hash2);
    print_hex("流式哈希:   ", hash2, 32);

    /* 两种方式结果应相同 */
    if (memcmp(hash1, hash2, 32) != 0) {
        fprintf(stderr, "错误: 哈希结果不一致!\n");
        return 1;
    }
    printf("✓ 两种方式结果一致\n");
    return 0;
}

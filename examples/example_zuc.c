/** @file example_zuc.c
 *  @brief ZUC 流密码示例：密钥流生成和 EEA3 加解密
 *  @example example_zuc.c
 */
#include <stdio.h>
#include <string.h>
#include "simple_gmsm/zuc.h"

static void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s", label);
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    /* 128 位密钥和初始向量 */
    const unsigned char key[16] = {
        0x3D,0x4C,0x4B,0xE9,0x6A,0x82,0xFD,0xAE,
        0xB5,0x8F,0x64,0x1D,0xB1,0x7B,0x45,0x5B
    };
    const unsigned char iv[16] = {
        0x84,0x31,0x9A,0xA8,0xDE,0x69,0x15,0xCA,
        0x1F,0x6B,0xDA,0x6B,0xFB,0xD8,0xC7,0x66
    };

    /* ========== 密钥流生成 ========== */
    printf("=== ZUC 密钥流生成 ===\n");
    {
        zuc_state_t state;
        zuc_init(&state, key, iv);
        printf("前 8 个密钥字: ");
        for (int i = 0; i < 8; i++)
            printf("%08x ", zuc_generate(&state));
        printf("\n\n");
    }

    /* ========== EEA3 加解密 ========== */
    printf("=== EEA3 加解密 ===\n");
    {
        unsigned int count = 0x66035492;
        unsigned int bearer = 0x0F;
        unsigned int direction = 0;

        unsigned char plain[24] = "ZUC EEA3 stream test";
        unsigned long plen = strlen((const char *)plain);
        unsigned char cipher[24], dec[24];

        /* 加密 */
        zuc_eea3(key, count, bearer, direction,
                 plain, cipher, (unsigned int)(plen * 8));
        print_hex("明文: ", plain, plen);
        print_hex("密文: ", cipher, plen);

        /* 解密（EEA3 是对称操作，再加密一次即可还原） */
        zuc_eea3(key, count, bearer, direction,
                 cipher, dec, (unsigned int)(plen * 8));
        print_hex("解密: ", dec, plen);

        if (memcmp(plain, dec, plen) != 0) {
            fprintf(stderr, "EEA3 解密失败!\n");
            return 1;
        }
        printf("✓ EEA3 加解密正确\n");
    }

    return 0;
}

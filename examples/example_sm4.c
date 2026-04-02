/** @file example_sm4.c
 *  @brief SM4 分组密码示例：演示 ECB、CBC、GCM 模式
 *  @example example_sm4.c
 */
#include <stdio.h>
#include <string.h>
#include "simple_gmsm/sm4.h"

static void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s", label);
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    /* 128 位密钥和初始向量 */
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };

    /* ========== ECB 模式 (单个 16 字节分组) ========== */
    printf("=== ECB 模式 ===\n");
    {
        unsigned char block[16] = "0123456789abcdef";
        unsigned char enc[16], dec[16];
        SM4_KEY ks;
        sm4_set_key(key, &ks);
        sm4_encrypt(block, enc, &ks);
        sm4_decrypt(enc, dec, &ks);
        print_hex("明文:   ", block, 16);
        print_hex("密文:   ", enc, 16);
        print_hex("解密:   ", dec, 16);
        if (memcmp(block, dec, 16) != 0) { fprintf(stderr, "ECB 解密失败!\n"); return 1; }
        printf("✓ ECB 正确\n\n");
    }

    /* ========== CBC 模式 ========== */
    printf("=== CBC 模式 ===\n");
    {
        const unsigned char plain[] = "SM4-CBC mode test, need padding!";  /* 32 字节 */
        unsigned long plen = strlen((const char *)plain);
        unsigned char enc[64], dec[64];
        unsigned long elen = 0, dlen = 0;

        sm4_cbc_encrypt(key, iv, plain, plen, enc, &elen);
        sm4_cbc_decrypt(key, iv, enc, elen, dec, &dlen);
        print_hex("明文:   ", plain, plen);
        print_hex("密文:   ", enc, elen);
        print_hex("解密:   ", dec, dlen);
        if (dlen != plen || memcmp(plain, dec, plen) != 0) {
            fprintf(stderr, "CBC 解密失败!\n"); return 1;
        }
        printf("✓ CBC 正确\n\n");
    }

    /* ========== GCM 模式 (带附加认证数据) ========== */
    printf("=== GCM 模式 ===\n");
    {
        const unsigned char gcm_iv[12] = {0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,
                                          0xDB,0xAD,0xDE,0xCA,0xF8,0x88};
        const unsigned char aad[] = "additional auth data";
        const unsigned char plain[] = "GCM authenticated encryption!";
        unsigned long plen = strlen((const char *)plain);
        unsigned char enc[64], dec[64], tag[16];

        int r = sm4_gcm_encrypt(key, gcm_iv, sizeof(gcm_iv),
                                aad, strlen((const char *)aad),
                                plain, plen, enc, tag);
        if (!r) { fprintf(stderr, "GCM 加密失败!\n"); return 1; }

        print_hex("密文:   ", enc, plen);
        print_hex("标签:   ", tag, 16);

        r = sm4_gcm_decrypt(key, gcm_iv, sizeof(gcm_iv),
                            aad, strlen((const char *)aad),
                            enc, plen, dec, tag);
        if (!r) { fprintf(stderr, "GCM 解密/验证失败!\n"); return 1; }

        if (memcmp(plain, dec, plen) != 0) {
            fprintf(stderr, "GCM 解密结果不匹配!\n"); return 1;
        }
        printf("✓ GCM 正确\n");
    }

    return 0;
}

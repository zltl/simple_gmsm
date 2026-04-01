#include "test_common.h"
#include "simple_gmsm/sm4.h"

/* GB/T 32907-2016 standard test vector */
static const unsigned char tv_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const unsigned char tv_plain[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const unsigned char tv_cipher[16] = {
    0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
    0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
};

/* Result after 1,000,000 rounds of encryption */
static const unsigned char tv_million[16] = {
    0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F,
    0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66
};

TEST_CASE(test_sm4_encrypt) {
    SM4_KEY ks;
    unsigned char out[16];
    sm4_set_key(tv_key, &ks);
    sm4_encrypt(tv_plain, out, &ks);
    ASSERT_MEM_EQ(out, tv_cipher, 16);
}

TEST_CASE(test_sm4_decrypt) {
    SM4_KEY ks;
    unsigned char out[16];
    sm4_set_key(tv_key, &ks);
    sm4_decrypt(tv_cipher, out, &ks);
    ASSERT_MEM_EQ(out, tv_plain, 16);
}

TEST_CASE(test_sm4_encrypt_decrypt_roundtrip) {
    SM4_KEY ks;
    unsigned char encrypted[16], decrypted[16];
    sm4_set_key(tv_key, &ks);
    sm4_encrypt(tv_plain, encrypted, &ks);
    sm4_decrypt(encrypted, decrypted, &ks);
    ASSERT_MEM_EQ(decrypted, tv_plain, 16);
}

TEST_CASE(test_sm4_1000_rounds) {
    /* Fast variant: 1000 rounds of encryption */
    SM4_KEY ks;
    sm4_set_key(tv_key, &ks);
    unsigned char buf[16];
    memcpy(buf, tv_plain, 16);
    for (int i = 0; i < 1000; i++) {
        unsigned char tmp[16];
        sm4_encrypt(buf, tmp, &ks);
        memcpy(buf, tmp, 16);
    }
    /* We don't have a reference for 1000 rounds, just verify it's deterministic
       by doing it again */
    unsigned char buf2[16];
    memcpy(buf2, tv_plain, 16);
    for (int i = 0; i < 1000; i++) {
        unsigned char tmp[16];
        sm4_encrypt(buf2, tmp, &ks);
        memcpy(buf2, tmp, 16);
    }
    ASSERT_MEM_EQ(buf, buf2, 16);
}

TEST_CASE(test_sm4_million_rounds) {
    /* GB/T 32907-2016: 1,000,000 rounds of encryption */
    SM4_KEY ks;
    sm4_set_key(tv_key, &ks);
    unsigned char buf[16];
    memcpy(buf, tv_plain, 16);
    for (int i = 0; i < 1000000; i++) {
        unsigned char tmp[16];
        sm4_encrypt(buf, tmp, &ks);
        memcpy(buf, tmp, 16);
    }
    ASSERT_MEM_EQ(buf, tv_million, 16);
}

void test_sm4_suite(void) {
    TEST_SUITE("SM4 Block Cipher");
    RUN_TEST(test_sm4_encrypt);
    RUN_TEST(test_sm4_decrypt);
    RUN_TEST(test_sm4_encrypt_decrypt_roundtrip);
    RUN_TEST(test_sm4_1000_rounds);
    RUN_TEST(test_sm4_million_rounds);
}

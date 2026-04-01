#include "test_common.h"
#include "simple_gmsm/zuc.h"

/* 3GPP TS 35.221 Test Vector Set 1: all-zero key and IV */
TEST_CASE(test_zuc_vector1) {
    unsigned char key[16] = {0};
    unsigned char iv[16]  = {0};
    zuc_state_t state;
    zuc_init(&state, key, iv);

    unsigned int z1 = zuc_generate(&state);
    unsigned int z2 = zuc_generate(&state);

    ASSERT_EQ(z1, (long long)0x27BEDE74);
    ASSERT_EQ(z2, (long long)0x018082DA);
}

/* 3GPP TS 35.221 Test Vector Set 2: all-FF key and IV */
TEST_CASE(test_zuc_vector2) {
    unsigned char key[16], iv[16];
    memset(key, 0xFF, 16);
    memset(iv, 0xFF, 16);
    zuc_state_t state;
    zuc_init(&state, key, iv);

    unsigned int z1 = zuc_generate(&state);
    unsigned int z2 = zuc_generate(&state);

    ASSERT_EQ(z1, (long long)0x0657CFA0);
    ASSERT_EQ(z2, (long long)0x7096398B);
}

/* 3GPP TS 35.221 Test Vector Set 3 */
TEST_CASE(test_zuc_vector3) {
    unsigned char key[16] = {
        0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE,
        0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B, 0x45, 0x5B
    };
    unsigned char iv[16] = {
        0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA,
        0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8, 0xC7, 0x66
    };
    zuc_state_t state;
    zuc_init(&state, key, iv);

    unsigned int z1 = zuc_generate(&state);
    unsigned int z2 = zuc_generate(&state);

    ASSERT_EQ(z1, (long long)0x14F1C272);
    ASSERT_EQ(z2, (long long)0x3279C419);
}

/* EEA3 encrypt/decrypt round-trip */
TEST_CASE(test_zuc_eea3_basic) {
    unsigned char key[16] = {
        0x17, 0x3D, 0x14, 0xBA, 0x50, 0x03, 0x73, 0x1D,
        0x7A, 0x60, 0x04, 0x94, 0x70, 0xF0, 0x0A, 0x29
    };
    unsigned int count = 0x66035492;
    unsigned int bearer = 0x0F;
    unsigned int direction = 0;

    unsigned char plaintext[32];
    for (int i = 0; i < 32; i++) plaintext[i] = (unsigned char)(i * 7 + 3);

    unsigned char ciphertext[32];
    unsigned char decrypted[32];

    zuc_eea3(key, count, bearer, direction, plaintext, ciphertext, 32 * 8);
    zuc_eea3(key, count, bearer, direction, ciphertext, decrypted, 32 * 8);

    ASSERT_MEM_EQ(decrypted, plaintext, 32);
}

void test_zuc_suite(void) {
    TEST_SUITE("ZUC");
    RUN_TEST(test_zuc_vector1);
    RUN_TEST(test_zuc_vector2);
    RUN_TEST(test_zuc_vector3);
    RUN_TEST(test_zuc_eea3_basic);
}

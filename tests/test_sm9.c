#include "test_common.h"
#include "simple_gmsm/sm9.h"

/* Test that G1 generator is on curve: y^2 = x^3 + 5 (mod p) */
TEST_CASE(test_sm9_g1_on_curve) {
    big_t lhs, rhs, tmp;
    big_init(&lhs); big_init(&rhs); big_init(&tmp);

    /* lhs = P1.y^2 mod p */
    big_mul(&tmp, &sm9_P1.y, &sm9_P1.y);
    big_mod(&lhs, &tmp, &sm9_p);

    /* rhs = P1.x^3 + 5 mod p */
    big_mul(&tmp, &sm9_P1.x, &sm9_P1.x);
    big_mod(&rhs, &tmp, &sm9_p);
    big_mul(&tmp, &rhs, &sm9_P1.x);
    big_mod(&rhs, &tmp, &sm9_p);
    big_add(&tmp, &rhs, &sm9_b);
    big_mod(&rhs, &tmp, &sm9_p);

    ASSERT_EQ(big_cmp(&lhs, &rhs), 0);

    big_destroy(&lhs); big_destroy(&rhs); big_destroy(&tmp);
}

/* Test SM9 parameter initialization */
TEST_CASE(test_sm9_params) {
    ASSERT_TRUE(big_cmp(&sm9_p, &big_zero) > 0);
    ASSERT_TRUE(big_cmp(&sm9_n, &big_zero) > 0);
    /* For BN curves, p > n */
    ASSERT_TRUE(big_cmp(&sm9_p, &sm9_n) > 0);
}

/* Test sign master key generation */
TEST_CASE(test_sm9_sign_master_keygen) {
    sm9_sign_master_key_t mk;
    memset(&mk, 0, sizeof(mk));
    sm9_sign_master_keygen(&mk);
    /* ks should be in [1, N-1] */
    ASSERT_TRUE(big_cmp(&mk.ks, &big_zero) > 0);
    ASSERT_TRUE(big_cmp(&mk.ks, &sm9_n) < 0);
}

/* Test enc master key generation */
TEST_CASE(test_sm9_enc_master_keygen) {
    sm9_enc_master_key_t mk;
    memset(&mk, 0, sizeof(mk));
    sm9_enc_master_keygen(&mk);
    ASSERT_TRUE(big_cmp(&mk.ke, &big_zero) > 0);
    ASSERT_TRUE(big_cmp(&mk.ke, &sm9_n) < 0);
}

/* Test encrypt/decrypt roundtrip — short message (< 16 bytes) */
TEST_CASE(test_sm9_encrypt_decrypt_short) {
    sm9_enc_master_key_t mk;
    sm9_enc_user_key_t uk;
    const unsigned char* id = (const unsigned char*)"alice@example.com";
    unsigned long idlen = 17;
    unsigned char msg[] = "Hello SM9!";
    unsigned long msglen = 10;
    unsigned char ct[256];
    unsigned long ctlen = 0;
    unsigned char dec[256];
    unsigned long declen = 0;

    sm9_enc_master_keygen(&mk);
    int r = sm9_enc_user_key_extract(&uk, &mk, id, idlen);
    ASSERT_EQ(r, 1);

    r = sm9_encrypt(ct, sizeof(ct), &ctlen, msg, msglen, id, idlen, &mk);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(ctlen, 65 + msglen + 32);

    r = sm9_decrypt(dec, sizeof(dec), &declen, ct, ctlen, id, idlen, &uk);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(declen, msglen);
    ASSERT_MEM_EQ(dec, msg, msglen);
}

/* Test encrypt/decrypt roundtrip — long message (> 16 bytes, catches keystream reuse) */
TEST_CASE(test_sm9_encrypt_decrypt_long) {
    sm9_enc_master_key_t mk;
    sm9_enc_user_key_t uk;
    const unsigned char* id = (const unsigned char*)"bob@example.com";
    unsigned long idlen = 15;
    unsigned char msg[64];
    unsigned long msglen = sizeof(msg);
    unsigned char ct[256];
    unsigned long ctlen = 0;
    unsigned char dec[256];
    unsigned long declen = 0;
    unsigned long i;

    for (i = 0; i < msglen; i++) msg[i] = (unsigned char)i;

    sm9_enc_master_keygen(&mk);
    int r = sm9_enc_user_key_extract(&uk, &mk, id, idlen);
    ASSERT_EQ(r, 1);

    r = sm9_encrypt(ct, sizeof(ct), &ctlen, msg, msglen, id, idlen, &mk);
    ASSERT_EQ(r, 1);

    r = sm9_decrypt(dec, sizeof(dec), &declen, ct, ctlen, id, idlen, &uk);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(declen, msglen);
    ASSERT_MEM_EQ(dec, msg, msglen);
}

/* Test that tampered ciphertext fails MAC verification */
TEST_CASE(test_sm9_decrypt_tamper) {
    sm9_enc_master_key_t mk;
    sm9_enc_user_key_t uk;
    const unsigned char* id = (const unsigned char*)"carol@example.com";
    unsigned long idlen = 17;
    unsigned char msg[] = "Tamper test";
    unsigned long msglen = 11;
    unsigned char ct[256];
    unsigned long ctlen = 0;
    unsigned char dec[256];
    unsigned long declen = 0;

    sm9_enc_master_keygen(&mk);
    sm9_enc_user_key_extract(&uk, &mk, id, idlen);
    sm9_encrypt(ct, sizeof(ct), &ctlen, msg, msglen, id, idlen, &mk);

    /* Flip a byte in C2 */
    ct[66] ^= 0xFF;

    int r = sm9_decrypt(dec, sizeof(dec), &declen, ct, ctlen, id, idlen, &uk);
    ASSERT_EQ(r, 0);
}

void test_sm9_suite(void) {
    TEST_SUITE("SM9");
    RUN_TEST(test_sm9_params);
    RUN_TEST(test_sm9_g1_on_curve);
    RUN_TEST(test_sm9_sign_master_keygen);
    RUN_TEST(test_sm9_enc_master_keygen);
    RUN_TEST(test_sm9_encrypt_decrypt_short);
    RUN_TEST(test_sm9_encrypt_decrypt_long);
    RUN_TEST(test_sm9_decrypt_tamper);
}

#include "test_common.h"
#include "simple_gmsm/sm2.h"

TEST_CASE(test_sm2_on_curve) {
    ASSERT_TRUE(sm2_on_curve_p(&sm2_gx, &sm2_gy));
}

TEST_CASE(test_sm2_scalar_mult) {
    big_t rx, ry;
    big_init(&rx);
    big_init(&ry);

    sm2_scalar_mult(&rx, &ry, &sm2_gx, &sm2_gy, &big_one);
    ASSERT_EQ(big_cmp(&rx, &sm2_gx), 0);
    ASSERT_EQ(big_cmp(&ry, &sm2_gy), 0);

    big_destroy(&rx);
    big_destroy(&ry);
}

TEST_CASE(test_sm2_add_double) {
    big_t ax, ay, dx, dy;
    big_init(&ax);
    big_init(&ay);
    big_init(&dx);
    big_init(&dy);

    /* P + P via add */
    sm2_add(&ax, &ay, (big_t*)&sm2_gx, (big_t*)&sm2_gy,
            (big_t*)&sm2_gx, (big_t*)&sm2_gy);
    /* 2P via double */
    sm2_double(&dx, &dy, (big_t*)&sm2_gx, (big_t*)&sm2_gy);

    ASSERT_EQ(big_cmp(&ax, &dx), 0);
    ASSERT_EQ(big_cmp(&ay, &dy), 0);
    ASSERT_TRUE(sm2_on_curve_p(&ax, &ay));

    big_destroy(&ax);
    big_destroy(&ay);
    big_destroy(&dx);
    big_destroy(&dy);
}

TEST_CASE(test_sm2_sign_verify) {
    big_t d, px, py;
    big_init(&d);
    big_init(&px);
    big_init(&py);

    sm2_gen_key(&d, &px, &py);
    ASSERT_TRUE(sm2_on_curve_p(&px, &py));

    unsigned char id[] = "1234567812345678";
    unsigned char za[32];
    sm2_za(za, id, 16, &px, &py);

    unsigned char msg[] = "hello sm2 sign test";
    unsigned char sig[64];
    sm2_sign_generate(sig, msg, sizeof(msg) - 1, za, &d);

    int ok = sm2_sign_verify(sig, msg, sizeof(msg) - 1, za, &px, &py);
    ASSERT_TRUE(ok);

    big_destroy(&d);
    big_destroy(&px);
    big_destroy(&py);
}

TEST_CASE(test_sm2_sign_verify_bad) {
    big_t d, px, py;
    big_init(&d);
    big_init(&px);
    big_init(&py);

    sm2_gen_key(&d, &px, &py);

    unsigned char id[] = "1234567812345678";
    unsigned char za[32];
    sm2_za(za, id, 16, &px, &py);

    unsigned char msg[] = "hello sm2 sign test";
    unsigned char sig[64];
    sm2_sign_generate(sig, msg, sizeof(msg) - 1, za, &d);

    /* Tamper with the signature */
    sig[0] ^= 0xFF;

    int ok = sm2_sign_verify(sig, msg, sizeof(msg) - 1, za, &px, &py);
    ASSERT_FALSE(ok);

    big_destroy(&d);
    big_destroy(&px);
    big_destroy(&py);
}

TEST_CASE(test_sm2_encrypt_decrypt) {
    big_t d, px, py;
    big_init(&d);
    big_init(&px);
    big_init(&py);

    sm2_gen_key(&d, &px, &py);

    unsigned char plaintext[] = "SM2 encryption test!";
    unsigned long plen = sizeof(plaintext) - 1;
    unsigned long clen = 1 + 32 * 2 + 32 + plen;
    unsigned char cipher[256];
    unsigned char decrypted[256];

    int ret = sm2_encrypt(cipher, clen, plaintext, plen, &px, &py);
    ASSERT_TRUE(ret);

    ret = sm2_decrypt(decrypted, (long)plen, cipher, (long)clen, &d);
    ASSERT_TRUE(ret);
    ASSERT_MEM_EQ(decrypted, plaintext, plen);

    big_destroy(&d);
    big_destroy(&px);
    big_destroy(&py);
}

TEST_CASE(test_sm2_za) {
    big_t d, px, py;
    big_init(&d);
    big_init(&px);
    big_init(&py);

    sm2_gen_key(&d, &px, &py);

    unsigned char id[] = "1234567812345678";
    unsigned char za1[32], za2[32];

    sm2_za(za1, id, 16, &px, &py);
    sm2_za(za2, id, 16, &px, &py);

    /* Same inputs must produce same ZA */
    ASSERT_MEM_EQ(za1, za2, 32);

    /* ZA should not be all zeros */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (za1[i] != 0) { all_zero = 0; break; }
    }
    ASSERT_FALSE(all_zero);

    big_destroy(&d);
    big_destroy(&px);
    big_destroy(&py);
}

void test_sm2_suite(void) {
    TEST_SUITE("SM2");
    RUN_TEST(test_sm2_on_curve);
    RUN_TEST(test_sm2_scalar_mult);
    RUN_TEST(test_sm2_add_double);
    RUN_TEST(test_sm2_sign_verify);
    RUN_TEST(test_sm2_sign_verify_bad);
    RUN_TEST(test_sm2_encrypt_decrypt);
    RUN_TEST(test_sm2_za);
}

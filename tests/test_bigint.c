#include "test_common.h"
#include "simple_gmsm/big.h"

TEST_CASE(test_big_add) {
    big_t a, b, c;
    big_init(&a); big_init(&b); big_init(&c);

    /* 1 + 2 = 3 */
    big_set(&a, &big_one);
    big_set(&b, &big_two);
    big_add(&c, &a, &b);
    ASSERT_EQ(big_cmp(&c, &big_three), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&c);
}

TEST_CASE(test_big_sub) {
    big_t a, b, c;
    big_init(&a); big_init(&b); big_init(&c);

    /* 3 - 2 = 1 */
    big_set(&a, &big_three);
    big_set(&b, &big_two);
    big_sub(&c, &a, &b);
    ASSERT_EQ(big_cmp(&c, &big_one), 0);

    /* 1 - 1 = 0 */
    big_set(&a, &big_one);
    big_sub(&c, &a, &big_one);
    ASSERT_EQ(big_cmp(&c, &big_zero), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&c);
}

TEST_CASE(test_big_mul) {
    big_t a, b, c, expected;
    big_init(&a); big_init(&b); big_init(&c); big_init(&expected);

    /* 2 * 3 = 6 */
    big_set(&a, &big_two);
    big_set(&b, &big_three);
    big_mul(&c, &a, &b);

    /* Build 6 as 3+3 */
    big_add(&expected, &big_three, &big_three);
    ASSERT_EQ(big_cmp(&c, &expected), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&c); big_destroy(&expected);
}

TEST_CASE(test_big_mod) {
    big_t a, b, c;
    big_init(&a); big_init(&b); big_init(&c);

    /* 3 mod 2 = 1 */
    big_set(&a, &big_three);
    big_set(&b, &big_two);
    big_mod(&c, &a, &b);
    ASSERT_EQ(big_cmp(&c, &big_one), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&c);
}

TEST_CASE(test_big_cmp) {
    /* 0 < 1 < 2 < 3 */
    ASSERT_EQ(big_cmp(&big_zero, &big_one), -1);
    ASSERT_EQ(big_cmp(&big_one, &big_one), 0);
    ASSERT_EQ(big_cmp(&big_two, &big_one), 1);
    ASSERT_EQ(big_cmp(&big_three, &big_two), 1);
    ASSERT_EQ(big_cmp(&big_zero, &big_zero), 0);
}

TEST_CASE(test_big_from_to_bytes) {
    big_t a;
    big_init(&a);

    /* Round-trip: load 4 bytes, export, compare */
    unsigned char input[4] = { 0x01, 0x02, 0x03, 0x04 };
    big_from_bytes(&a, input, 4);

    unsigned char output[MAX_INT_BYTE];
    unsigned long out_len = sizeof(output);
    big_to_bytes(output, &out_len, &a);

    ASSERT_EQ(out_len, 4);
    ASSERT_MEM_EQ(output, input, 4);

    big_destroy(&a);
}

TEST_CASE(test_big_from_to_bytes_large) {
    big_t a;
    big_init(&a);

    /* 32-byte value (typical for SM2 scalars) */
    unsigned char input[32] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    big_from_bytes(&a, input, 32);

    unsigned char output[MAX_INT_BYTE];
    unsigned long out_len = sizeof(output);
    big_to_bytes(output, &out_len, &a);

    ASSERT_EQ(out_len, 32);
    ASSERT_MEM_EQ(output, input, 32);

    big_destroy(&a);
}

TEST_CASE(test_big_add_large) {
    big_t a, b, c, expected;
    big_init(&a); big_init(&b); big_init(&c); big_init(&expected);

    /* 0xFF + 0x01 = 0x0100 */
    unsigned char a_bytes[1] = { 0xFF };
    unsigned char b_bytes[1] = { 0x01 };
    unsigned char expected_bytes[2] = { 0x01, 0x00 };

    big_from_bytes(&a, a_bytes, 1);
    big_from_bytes(&b, b_bytes, 1);
    big_from_bytes(&expected, expected_bytes, 2);

    big_add(&c, &a, &b);
    ASSERT_EQ(big_cmp(&c, &expected), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&c); big_destroy(&expected);
}

TEST_CASE(test_big_from_bytes_zero) {
    big_t a;
    unsigned char input[4] = { 0x00, 0x00, 0x00, 0x00 };
    unsigned char output[MAX_INT_BYTE];
    unsigned long out_len = sizeof(output);

    big_init(&a);

    big_from_bytes(&a, input, 4);
    ASSERT_EQ(big_cmp(&a, &big_zero), 0);

    big_to_bytes(output, &out_len, &a);
    ASSERT_EQ(out_len, 0);

    big_destroy(&a);
}

TEST_CASE(test_big_add_alias) {
    big_t a, b, expected;
    unsigned char a_bytes[1] = { 0xFF };
    unsigned char b_bytes[1] = { 0x01 };
    unsigned char expected_bytes[2] = { 0x01, 0x00 };

    big_init(&a); big_init(&b); big_init(&expected);

    big_from_bytes(&a, a_bytes, 1);
    big_from_bytes(&b, b_bytes, 1);
    big_from_bytes(&expected, expected_bytes, 2);

    big_add(&a, &a, &b);
    ASSERT_EQ(big_cmp(&a, &expected), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&expected);
}

TEST_CASE(test_big_sub_alias) {
    big_t a, b, expected;
    unsigned char a_bytes[2] = { 0x01, 0x00 };
    unsigned char b_bytes[1] = { 0x01 };
    unsigned char expected_bytes[1] = { 0xFF };

    big_init(&a); big_init(&b); big_init(&expected);

    big_from_bytes(&a, a_bytes, 2);
    big_from_bytes(&b, b_bytes, 1);
    big_from_bytes(&expected, expected_bytes, 1);

    big_sub(&a, &a, &b);
    ASSERT_EQ(big_cmp(&a, &expected), 0);

    big_destroy(&a); big_destroy(&b); big_destroy(&expected);
}

TEST_CASE(test_big_inv_small_prime) {
    big_t a, mod, inv, tmp;
    unsigned char a_bytes[1] = { 0x05 };
    unsigned char mod_bytes[1] = { 0x11 };

    big_init(&a); big_init(&mod); big_init(&inv); big_init(&tmp);

    big_from_bytes(&a, a_bytes, 1);
    big_from_bytes(&mod, mod_bytes, 1);

    ASSERT_TRUE(big_inv(&inv, &a, &mod));
    big_mul(&tmp, &a, &inv);
    big_mod(&tmp, &tmp, &mod);
    ASSERT_EQ(big_cmp(&tmp, &big_one), 0);

    big_destroy(&a); big_destroy(&mod); big_destroy(&inv); big_destroy(&tmp);
}

TEST_CASE(test_big_inv_large_roundtrip) {
    big_t a, mod, inv, tmp;
    unsigned char mod_bytes[32] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    unsigned char a_bytes[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
    };

    big_init(&a); big_init(&mod); big_init(&inv); big_init(&tmp);

    big_from_bytes(&a, a_bytes, 32);
    big_from_bytes(&mod, mod_bytes, 32);

    ASSERT_TRUE(big_inv(&inv, &a, &mod));
    big_mul(&tmp, &a, &inv);
    big_mod(&tmp, &tmp, &mod);
    ASSERT_EQ(big_cmp(&tmp, &big_one), 0);

    big_destroy(&a); big_destroy(&mod); big_destroy(&inv); big_destroy(&tmp);
}

void test_bigint_suite(void) {
    TEST_SUITE("Big Integer");
    RUN_TEST(test_big_add);
    RUN_TEST(test_big_sub);
    RUN_TEST(test_big_mul);
    RUN_TEST(test_big_mod);
    RUN_TEST(test_big_cmp);
    RUN_TEST(test_big_from_to_bytes);
    RUN_TEST(test_big_from_to_bytes_large);
    RUN_TEST(test_big_add_large);
    RUN_TEST(test_big_from_bytes_zero);
    RUN_TEST(test_big_add_alias);
    RUN_TEST(test_big_sub_alias);
    RUN_TEST(test_big_inv_small_prime);
    RUN_TEST(test_big_inv_large_roundtrip);
}

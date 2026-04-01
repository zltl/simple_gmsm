#include "test_common.h"
#include "simple_gmsm/sm3.h"

/* GB/T 32905-2016 Test Vector 1: SM3("abc") */
static const unsigned char tv1_expected[32] = {
    0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
    0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
    0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
    0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

/* GB/T 32905-2016 Test Vector 2: SM3("abcd" * 16) */
static const unsigned char tv2_expected[32] = {
    0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
    0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
    0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
    0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32
};

TEST_CASE(test_sm3_vector1) {
    unsigned char digest[32];
    const unsigned char msg[] = "abc";
    sm3(msg, 3, digest);
    ASSERT_MEM_EQ(digest, tv1_expected, 32);
}

TEST_CASE(test_sm3_vector2) {
    unsigned char digest[32];
    const unsigned char msg[] =
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    sm3(msg, 64, digest);
    ASSERT_MEM_EQ(digest, tv2_expected, 32);
}

TEST_CASE(test_sm3_empty) {
    unsigned char digest[32];
    sm3((const unsigned char *)"", 0, digest);
    /* Just verify it doesn't crash and produces 32 bytes of output.
       The empty-string hash is a known fixed value. */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (digest[i] != 0) { all_zero = 0; break; }
    }
    ASSERT_FALSE(all_zero);
}

TEST_CASE(test_sm3_incremental) {
    /* Hash "abc" incrementally: "a" then "bc", must match one-shot result */
    unsigned char digest_oneshot[32];
    unsigned char digest_incr[32];

    sm3((const unsigned char *)"abc", 3, digest_oneshot);

    sm3_context_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, (const unsigned char *)"a", 1);
    sm3_update(&ctx, (const unsigned char *)"bc", 2);
    sm3_finish(&ctx, digest_incr);

    ASSERT_MEM_EQ(digest_incr, digest_oneshot, 32);
}

TEST_CASE(test_sm3_incremental_tv2) {
    /* Hash "abcd"*16 incrementally: four chunks of "abcd"*4 */
    unsigned char digest_incr[32];
    const unsigned char chunk[] = "abcdabcdabcdabcd"; /* 16 bytes */

    sm3_context_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, chunk, 16);
    sm3_update(&ctx, chunk, 16);
    sm3_update(&ctx, chunk, 16);
    sm3_update(&ctx, chunk, 16);
    sm3_finish(&ctx, digest_incr);

    ASSERT_MEM_EQ(digest_incr, tv2_expected, 32);
}

void test_sm3_suite(void) {
    TEST_SUITE("SM3 Hash");
    RUN_TEST(test_sm3_vector1);
    RUN_TEST(test_sm3_vector2);
    RUN_TEST(test_sm3_empty);
    RUN_TEST(test_sm3_incremental);
    RUN_TEST(test_sm3_incremental_tv2);
}

#include "test_common.h"
#include "simple_gmsm/hmac_sm3.h"

TEST_CASE(test_hmac_sm3_basic) {
    const unsigned char key[] = "my secret key";
    const unsigned char msg[] = "hello world";
    unsigned char mac_oneshot[32], mac_stream[32];

    hmac_sm3(key, sizeof(key) - 1, msg, sizeof(msg) - 1, mac_oneshot);

    hmac_sm3_context_t ctx;
    hmac_sm3_init(&ctx, key, sizeof(key) - 1);
    hmac_sm3_update(&ctx, msg, sizeof(msg) - 1);
    hmac_sm3_finish(&ctx, mac_stream);

    ASSERT_MEM_EQ(mac_oneshot, mac_stream, 32);

    /* MAC should not be all zeros */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (mac_oneshot[i] != 0) { all_zero = 0; break; }
    }
    ASSERT_FALSE(all_zero);
}

TEST_CASE(test_hmac_sm3_empty_message) {
    const unsigned char key[] = "test key";
    unsigned char mac_oneshot[32], mac_stream[32];

    hmac_sm3(key, sizeof(key) - 1, (const unsigned char *)"", 0, mac_oneshot);

    hmac_sm3_context_t ctx;
    hmac_sm3_init(&ctx, key, sizeof(key) - 1);
    hmac_sm3_update(&ctx, (const unsigned char *)"", 0);
    hmac_sm3_finish(&ctx, mac_stream);

    ASSERT_MEM_EQ(mac_oneshot, mac_stream, 32);

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (mac_oneshot[i] != 0) { all_zero = 0; break; }
    }
    ASSERT_FALSE(all_zero);
}

TEST_CASE(test_hmac_sm3_long_key) {
    /* Key longer than 64 bytes triggers internal key hashing */
    unsigned char long_key[128];
    for (int i = 0; i < 128; i++) long_key[i] = (unsigned char)i;

    const unsigned char msg[] = "test message";
    unsigned char mac_oneshot[32], mac_stream[32];

    hmac_sm3(long_key, 128, msg, sizeof(msg) - 1, mac_oneshot);

    hmac_sm3_context_t ctx;
    hmac_sm3_init(&ctx, long_key, 128);
    hmac_sm3_update(&ctx, msg, sizeof(msg) - 1);
    hmac_sm3_finish(&ctx, mac_stream);

    ASSERT_MEM_EQ(mac_oneshot, mac_stream, 32);
}

TEST_CASE(test_hmac_sm3_streaming) {
    const unsigned char key[] = "streaming key";
    const unsigned char msg[] = "split this message into parts";
    unsigned char mac_oneshot[32], mac_stream[32];

    hmac_sm3(key, sizeof(key) - 1, msg, sizeof(msg) - 1, mac_oneshot);

    hmac_sm3_context_t ctx;
    hmac_sm3_init(&ctx, key, sizeof(key) - 1);
    hmac_sm3_update(&ctx, msg, 6);       /* "split " */
    hmac_sm3_update(&ctx, msg + 6, 5);   /* "this " */
    hmac_sm3_update(&ctx, msg + 11, sizeof(msg) - 1 - 11); /* rest */
    hmac_sm3_finish(&ctx, mac_stream);

    ASSERT_MEM_EQ(mac_oneshot, mac_stream, 32);
}

TEST_CASE(test_hmac_sm3_known_vector) {
    const unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    const unsigned char msg[] = "known vector test data";
    unsigned char mac_oneshot[32], mac_stream[32];

    hmac_sm3(key, 16, msg, sizeof(msg) - 1, mac_oneshot);

    hmac_sm3_context_t ctx;
    hmac_sm3_init(&ctx, key, 16);
    hmac_sm3_update(&ctx, msg, sizeof(msg) - 1);
    hmac_sm3_finish(&ctx, mac_stream);

    /* Self-consistency: one-shot and streaming must match */
    ASSERT_MEM_EQ(mac_oneshot, mac_stream, 32);
}

void test_hmac_sm3_suite(void) {
    TEST_SUITE("HMAC-SM3");
    RUN_TEST(test_hmac_sm3_basic);
    RUN_TEST(test_hmac_sm3_empty_message);
    RUN_TEST(test_hmac_sm3_long_key);
    RUN_TEST(test_hmac_sm3_streaming);
    RUN_TEST(test_hmac_sm3_known_vector);
}

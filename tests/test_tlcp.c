#include "test_common.h"
#include "simple_gmsm/tlcp.h"
#include <string.h>

/* Test PRF produces deterministic output */
TEST_CASE(test_tlcp_prf_deterministic) {
    unsigned char secret[] = "test secret";
    unsigned char seed[] = "test seed data";
    unsigned char out1[48], out2[48];

    tlcp_prf(secret, sizeof(secret) - 1, "test label", seed, sizeof(seed) - 1, out1, 48);
    tlcp_prf(secret, sizeof(secret) - 1, "test label", seed, sizeof(seed) - 1, out2, 48);

    ASSERT_MEM_EQ(out1, out2, 48);
}

/* Test PRF with different labels produces different output */
TEST_CASE(test_tlcp_prf_different_labels) {
    unsigned char secret[] = "test secret";
    unsigned char seed[] = "test seed data";
    unsigned char out1[32], out2[32];

    tlcp_prf(secret, sizeof(secret) - 1, "label A", seed, sizeof(seed) - 1, out1, 32);
    tlcp_prf(secret, sizeof(secret) - 1, "label B", seed, sizeof(seed) - 1, out2, 32);

    ASSERT_TRUE(memcmp(out1, out2, 32) != 0);
}

/* Test master secret derivation produces deterministic output */
TEST_CASE(test_tlcp_derive_master_secret) {
    unsigned char pms[48];
    unsigned char cr[32], sr[32];
    unsigned char ms1[48], ms2[48];

    memset(pms, 0xAB, sizeof(pms));
    memset(cr, 0x01, sizeof(cr));
    memset(sr, 0x02, sizeof(sr));

    tlcp_derive_master_secret(ms1, pms, sizeof(pms), cr, sr);
    tlcp_derive_master_secret(ms2, pms, sizeof(pms), cr, sr);

    ASSERT_MEM_EQ(ms1, ms2, 48);
}

/* Test key derivation produces valid key material */
TEST_CASE(test_tlcp_derive_keys) {
    tlcp_security_params_t params;
    memset(&params, 0, sizeof(params));

    memset(params.master_secret, 0xAA, TLCP_MASTER_SECRET_LEN);
    memset(params.client_random, 0x01, TLCP_RANDOM_LEN);
    memset(params.server_random, 0x02, TLCP_RANDOM_LEN);
    params.cipher_suite = TLCP_ECC_SM4_CBC_SM3;
    params.is_gcm = 0;

    tlcp_derive_keys(&params);

    unsigned char zeros[32];
    memset(zeros, 0, sizeof(zeros));
    ASSERT_TRUE(memcmp(params.client_write_key, zeros, 16) != 0);
    ASSERT_TRUE(memcmp(params.server_write_key, zeros, 16) != 0);
}

/* Test context initialization */
TEST_CASE(test_tlcp_ctx_init) {
    tlcp_context_t ctx;
    tlcp_ctx_init(&ctx);

    ASSERT_EQ(ctx.is_server, 0);
    ASSERT_TRUE(ctx.cipher_suite_count > 0);

    tlcp_ctx_set_server(&ctx, 1);
    ASSERT_EQ(ctx.is_server, 1);
}

/* Test connection initialization */
TEST_CASE(test_tlcp_conn_init) {
    tlcp_context_t ctx;
    tlcp_conn_t conn;

    tlcp_ctx_init(&ctx);
    tlcp_conn_init(&conn, &ctx);

    ASSERT_EQ(conn.state, TLCP_STATE_INIT);
    ASSERT_TRUE(conn.ctx == &ctx);
}

void test_tlcp_suite(void) {
    TEST_SUITE("TLCP");
    RUN_TEST(test_tlcp_prf_deterministic);
    RUN_TEST(test_tlcp_prf_different_labels);
    RUN_TEST(test_tlcp_derive_master_secret);
    RUN_TEST(test_tlcp_derive_keys);
    RUN_TEST(test_tlcp_ctx_init);
    RUN_TEST(test_tlcp_conn_init);
}

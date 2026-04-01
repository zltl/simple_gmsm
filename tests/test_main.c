#include "test_common.h"

int __test_pass_count = 0;
int __test_fail_count = 0;
int __test_total_count = 0;
int __test_current_failed = 0;

extern void test_sm3_suite(void);
extern void test_sm4_suite(void);
extern void test_bigint_suite(void);
extern void test_sm2_suite(void);
extern void test_hmac_sm3_suite(void);
extern void test_zuc_suite(void);
extern void test_sm9_suite(void);
extern void test_tlcp_suite(void);

int main(void) {
    extern void big_prepare(void);
    extern void sm2_init(void);
    extern void sm9_init(void);
    big_prepare();
    sm2_init();
    sm9_init();

    test_bigint_suite();
    test_sm3_suite();
    test_sm4_suite();
    test_sm2_suite();
    test_hmac_sm3_suite();
    test_zuc_suite();
    test_sm9_suite();
    test_tlcp_suite();

    TEST_SUMMARY();
}

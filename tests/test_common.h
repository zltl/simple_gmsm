#ifndef TEST_COMMON_H_
#define TEST_COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int __test_pass_count;
extern int __test_fail_count;
extern int __test_total_count;
extern int __test_current_failed;

#define TEST_CASE(name) static void name(void)

#define RUN_TEST(name) do { \
    printf("  Running %-50s", #name "..."); \
    fflush(stdout); \
    __test_current_failed = 0; \
    name(); \
    if (!__test_current_failed) { \
        printf(" PASS\n"); \
        __test_pass_count++; \
    } \
    __test_total_count++; \
} while(0)

#define TEST_SUITE(name) do { \
    printf("\n[%s]\n", name); \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        printf(" FAIL\n"); \
        printf("    Assertion failed: %s\n", #expr); \
        printf("    at %s:%d\n", __FILE__, __LINE__); \
        __test_fail_count++; \
        __test_current_failed = 1; \
        return; \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b) do { \
    long long __a = (long long)(a); \
    long long __b = (long long)(b); \
    if (__a != __b) { \
        printf(" FAIL\n"); \
        printf("    Expected: %lld, Got: %lld\n", __b, __a); \
        printf("    at %s:%d\n", __FILE__, __LINE__); \
        __test_fail_count++; \
        __test_current_failed = 1; \
        return; \
    } \
} while(0)

#define ASSERT_NEQ(a, b) do { \
    long long __a = (long long)(a); \
    long long __b = (long long)(b); \
    if (__a == __b) { \
        printf(" FAIL\n"); \
        printf("    Expected NOT: %lld\n", __a); \
        printf("    at %s:%d\n", __FILE__, __LINE__); \
        __test_fail_count++; \
        __test_current_failed = 1; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf(" FAIL\n"); \
        printf("    Memory comparison failed (len=%d)\n", (int)(len)); \
        printf("    Expected: "); \
        for (int __i = 0; __i < (int)(len); __i++) \
            printf("%02x", ((unsigned char*)(b))[__i]); \
        printf("\n    Got:      "); \
        for (int __i = 0; __i < (int)(len); __i++) \
            printf("%02x", ((unsigned char*)(a))[__i]); \
        printf("\n    at %s:%d\n", __FILE__, __LINE__); \
        __test_fail_count++; \
        __test_current_failed = 1; \
        return; \
    } \
} while(0)

#define TEST_SUMMARY() do { \
    printf("\n========================================\n"); \
    printf("Results: %d passed, %d failed, %d total\n", \
           __test_pass_count, __test_fail_count, __test_total_count); \
    if (__test_fail_count > 0) { \
        printf("FAILED\n"); \
    } else { \
        printf("ALL TESTS PASSED\n"); \
    } \
    printf("========================================\n"); \
    return __test_fail_count > 0 ? 1 : 0; \
} while(0)

#endif // TEST_COMMON_H_

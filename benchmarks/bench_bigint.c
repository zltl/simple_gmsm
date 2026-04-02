#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>

#include "simple_gmsm/big.h"

#define BENCH_SAMPLES 5

static volatile unsigned long bench_sink;

struct bench_stats {
    double best_ms;
    double total_ms;
};

static double elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0
         + (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

static void consume_big(const big_t* value) {
    bench_sink ^= (unsigned long)(unsigned int)value->sign;
}

static void print_metric(const char* name, int iterations,
                         const struct bench_stats* stats,
                         const big_t* value) {
    double best_ns_per_op = (stats->best_ms * 1000000.0) / iterations;
    double avg_ms = stats->total_ms / BENCH_SAMPLES;
    double avg_ns_per_op = (avg_ms * 1000000.0) / iterations;

    consume_big(value);
    printf("%s iterations=%d samples=%d best_ms=%.3f best_ns_per_op=%.1f avg_ms=%.3f avg_ns_per_op=%.1f\n",
           name, iterations, BENCH_SAMPLES,
           stats->best_ms, best_ns_per_op, avg_ms, avg_ns_per_op);
}

#define RUN_BENCH(stats, iterations, code_block) do { \
    int sample_idx; \
    (stats).best_ms = -1.0; \
    (stats).total_ms = 0.0; \
    for (sample_idx = 0; sample_idx < BENCH_SAMPLES; sample_idx++) { \
        clock_gettime(CLOCK_MONOTONIC, &start); \
        for (i = 0; i < (iterations); i++) { \
            code_block; \
        } \
        clock_gettime(CLOCK_MONOTONIC, &end); \
        sample_ms = elapsed_ms(start, end); \
        (stats).total_ms += sample_ms; \
        if ((stats).best_ms < 0.0 || sample_ms < (stats).best_ms) { \
            (stats).best_ms = sample_ms; \
        } \
    } \
} while (0)

static void init_inputs(big_t* small_a, big_t* small_b,
                        big_t* a, big_t* b, big_t* mod) {
    static unsigned char small_a_bytes[1] = { 0x7B };
    static unsigned char small_b_bytes[1] = { 0x31 };
    static unsigned char mod_bytes[32] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    static unsigned char a_bytes[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
    };
    static unsigned char b_bytes[32] = {
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78
    };

    big_from_bytes(small_a, small_a_bytes, sizeof(small_a_bytes));
    big_from_bytes(small_b, small_b_bytes, sizeof(small_b_bytes));
    big_from_bytes(a, a_bytes, sizeof(a_bytes));
    big_from_bytes(b, b_bytes, sizeof(b_bytes));
    big_from_bytes(mod, mod_bytes, sizeof(mod_bytes));
}

int main(void) {
    big_t small_a, small_b, a, b, mod, tmp, out;
    struct timespec start, end;
    struct bench_stats stats;
    double sample_ms;
    int i;

#ifdef USE_SLOW_BIGINT
    const char* impl = "slow";
#else
    const char* impl = "fast";
#endif

    big_prepare();
    big_init(&small_a);
    big_init(&small_b);
    big_init(&a);
    big_init(&b);
    big_init(&mod);
    big_init(&tmp);
    big_init(&out);

    init_inputs(&small_a, &small_b, &a, &b, &mod);

    printf("benchmark=bigint impl=%s\n", impl);

    RUN_BENCH(stats, 2000000, big_add(&out, &small_a, &small_b));
    print_metric("add", 2000000, &stats, &out);

    RUN_BENCH(stats, 2000000, big_sub(&out, &small_a, &small_b));
    print_metric("sub", 2000000, &stats, &out);

    RUN_BENCH(stats, 500000, big_mul(&tmp, &a, &b));
    print_metric("mul", 500000, &stats, &tmp);

    RUN_BENCH(stats, 400000, big_mod(&out, &a, &mod));
    print_metric("mod", 400000, &stats, &out);

    RUN_BENCH(stats, 300000, {
        big_mul(&tmp, &a, &b);
        big_mod(&out, &tmp, &mod);
    });
    print_metric("mul_mod", 300000, &stats, &out);

    RUN_BENCH(stats, 30000, big_inv(&out, &a, &mod));
    print_metric("inv", 30000, &stats, &out);

    printf("sink=%lu\n", bench_sink);

    big_destroy(&small_a);
    big_destroy(&small_b);
    big_destroy(&a);
    big_destroy(&b);
    big_destroy(&mod);
    big_destroy(&tmp);
    big_destroy(&out);
    big_finished();
    return 0;
}
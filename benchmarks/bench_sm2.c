#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>

#include "simple_gmsm/big.h"
#include "simple_gmsm/sm2.h"

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

static void consume_point(const big_t* x, const big_t* y) {
    bench_sink ^= (unsigned long)(unsigned int)x->sign;
    bench_sink ^= (unsigned long)(unsigned int)y->sign;
}

static void print_metric(const char* name, int iterations,
                         const struct bench_stats* stats,
                         const big_t* x, const big_t* y) {
    double best_ns_per_op = (stats->best_ms * 1000000.0) / iterations;
    double avg_ms = stats->total_ms / BENCH_SAMPLES;
    double avg_ns_per_op = (avg_ms * 1000000.0) / iterations;

    consume_point(x, y);
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

static void init_scalar(big_t* k) {
    static unsigned char scalar_bytes[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
    };

    big_from_bytes(k, scalar_bytes, sizeof(scalar_bytes));
}

int main(void) {
    big_t scalar, qx, qy, outx, outy;
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
    sm2_init();

    big_init(&scalar);
    big_init(&qx);
    big_init(&qy);
    big_init(&outx);
    big_init(&outy);

    init_scalar(&scalar);
    sm2_scalar_mult(&qx, &qy, &sm2_gx, &sm2_gy, &scalar);

    printf("benchmark=sm2 impl=%s\n", impl);

    RUN_BENCH(stats, 3000, sm2_double(&outx, &outy, &qx, &qy));
    print_metric("double", 3000, &stats, &outx, &outy);

    RUN_BENCH(stats, 3000, sm2_add(&outx, &outy, &sm2_gx, &sm2_gy, &qx, &qy));
    print_metric("add", 3000, &stats, &outx, &outy);

    RUN_BENCH(stats, 300, sm2_scalar_mult(&outx, &outy, &sm2_gx, &sm2_gy,
                                          &scalar));
    print_metric("scalar_base_mul", 300, &stats, &outx, &outy);

    printf("sink=%lu\n", bench_sink);

    big_destroy(&scalar);
    big_destroy(&qx);
    big_destroy(&qy);
    big_destroy(&outx);
    big_destroy(&outy);

    sm2_destroy();
    big_finished();
    return 0;
}
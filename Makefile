.PHONY: clean doxy latex libsimple_gmsm test examples bench bench-bigint bench-bigint-save bench-sm2 bench-sm2-save
.ONESHELL:

all: doxy latex libsimple_gmsm

PROJECT_ROOT_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ifeq ($(TARGET_DIR),)
	TARGET_DIR = $(PROJECT_ROOT_PATH)/target
endif

$(shell mkdir -p $(TARGET_DIR)/doc)

ifeq ($(CXX_STANDARD),)
    CXX_STANDARD := c++11
endif
ifeq ($(C_STANDARD),)
    C_STANDARD := c11
endif

COMMON_FLAG := -Werror -Wall -Wextra -pedantic -Wno-unused-result -fPIC -g -O2
COMMON_FLAG += -I$(PROJECT_ROOT_PATH)/include -I${PROJECT_ROOT_PATH}/include

CFLAGS += $(COMMON_FLAG) -std=$(C_STANDARD)
CXXFLAGS += $(COMMON_FLAG) -std=$(CXX_STANDARD)

ifdef USE_SLOW_BIGINT
COMMON_FLAG += -DUSE_SLOW_BIGINT
sources_c = $(filter-out fast_bigint.c, $(wildcard *.c))
else
sources_c = $(filter-out slow_dirty_bigint.c, $(wildcard *.c))
endif
sources_cxx = $(wildcard *.cc)
headers = $(wildcard *.h)
objs_c = $(patsubst %.c,$(TARGET_DIR)/%.c.o,$(sources_c))
objs_cxx = $(patsubst %.cc,$(TARGET_DIR)/%.cc.o,$(sources_cxx))

libsimple_gmsm: $(TARGET_DIR)/libsimple_gmsm.a $(TARGET_DIR)/libsimple_gmsm.so
$(TARGET_DIR)/%.c.o: %.c
	$(CC) -DSM_SHARED_LIBRARY -DSM_COMPILE_LIBRARY $(CFLAGS) -c $< -o $@ 
$(TARGET_DIR)/%.cc.o: %.cc
	$(CXX) -DSM_SHARED_LIBRARY -DSM_COMPILE_LIBRARY $(CXXFLAGS) -c $< -o $@ 
$(TARGET_DIR)/libsimple_gmsm.a: $(objs_c) $(objs_cxx)
	$(AR) rcs $@ $^
$(TARGET_DIR)/libsimple_gmsm.so: $(objs_c) $(objs_cxx)
	$(CXX) -DSM_SHARED_LIBRARY -DSM_COMPILE_LIBRARY -shared -o $@ $(LDFLAGS) $^

doxy:
	doxygen
latex: doxy
	cd target/doc/latex && make

# Tests
test_sources = $(wildcard tests/test_*.c)
test_objs = $(patsubst tests/%.c,$(TARGET_DIR)/tests/%.c.o,$(test_sources))

$(shell mkdir -p $(TARGET_DIR)/tests)

test: $(TARGET_DIR)/test_runner
	$(TARGET_DIR)/test_runner

$(TARGET_DIR)/tests/%.c.o: tests/%.c
	$(CC) $(CFLAGS) -I./tests -c $< -o $@

$(TARGET_DIR)/test_runner: $(test_objs) $(TARGET_DIR)/libsimple_gmsm.a
	$(CC) $(CFLAGS) -o $@ $^ -lm

# Examples
example_sources = $(wildcard examples/example_*.c)
example_bins = $(patsubst examples/%.c,$(TARGET_DIR)/examples/%,$(example_sources))

$(shell mkdir -p $(TARGET_DIR)/examples)

examples: $(example_bins)

$(TARGET_DIR)/examples/%: examples/%.c $(TARGET_DIR)/libsimple_gmsm.a
	$(CC) $(CFLAGS) -o $@ $< $(TARGET_DIR)/libsimple_gmsm.a -lm

# Benchmarks
bench_sources = $(wildcard benchmarks/bench_*.c)
bench_bins = $(patsubst benchmarks/%.c,$(TARGET_DIR)/benchmarks/%,$(bench_sources))

$(shell mkdir -p $(TARGET_DIR)/benchmarks $(TARGET_DIR)/benchmarks/results)

bench: bench-bigint bench-sm2

bench-bigint: $(TARGET_DIR)/benchmarks/bench_bigint
	$(TARGET_DIR)/benchmarks/bench_bigint

bench-bigint-save: $(TARGET_DIR)/benchmarks/bench_bigint
	@ts=$$(date -u +%Y%m%dT%H%M%SZ); \
	out="$(TARGET_DIR)/benchmarks/results/bigint-$$ts.txt"; \
	latest="$(TARGET_DIR)/benchmarks/results/bigint-latest.txt"; \
	{ \
		echo "timestamp=$$ts"; \
		echo "git_rev=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
		$(TARGET_DIR)/benchmarks/bench_bigint; \
	} | tee "$$out" | tee "$$latest"

bench-sm2: $(TARGET_DIR)/benchmarks/bench_sm2
	$(TARGET_DIR)/benchmarks/bench_sm2

bench-sm2-save: $(TARGET_DIR)/benchmarks/bench_sm2
	@ts=$$(date -u +%Y%m%dT%H%M%SZ); \
	out="$(TARGET_DIR)/benchmarks/results/sm2-$$ts.txt"; \
	latest="$(TARGET_DIR)/benchmarks/results/sm2-latest.txt"; \
	{ \
		echo "timestamp=$$ts"; \
		echo "git_rev=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
		$(TARGET_DIR)/benchmarks/bench_sm2; \
	} | tee "$$out" | tee "$$latest"

$(TARGET_DIR)/benchmarks/%: benchmarks/%.c $(TARGET_DIR)/libsimple_gmsm.a
	$(CC) $(CFLAGS) -o $@ $< $(TARGET_DIR)/libsimple_gmsm.a -lm

clean:
	rm -rf $(TARGET_DIR)

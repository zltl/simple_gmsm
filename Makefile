.PHONY: clean doxy latex libsimple_gmsm
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

COMMON_FLAG := -Werror -Wall -Wextra -pedantic -Wno-unused-result -fPIC -g
COMMON_FLAG += -I$(PROJECT_ROOT_PATH)/include -I${PROJECT_ROOT_PATH}/include

CFLAGS += $(COMMON_FLAG) -std=$(C_STANDARD)
CXXFLAGS += $(COMMON_FLAG) -std=$(CXX_STANDARD)

sources_c = $(wildcard *.c)
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
	cd target/doc && make


SHELL := /bin/bash

BUILD_DIR := build
BPFTOOL ?= $(shell if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then command -v bpftool; else find /usr/lib/linux-tools -name bpftool -print 2>/dev/null | sort -V | tail -n 1; fi)
CLANG ?= clang
CC ?= cc
SAN_CC ?= clang
PKG_CONFIG ?= pkg-config

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
BPF_ARCH := arm64
else
$(error Unsupported architecture for BPF target mapping: $(UNAME_M))
endif

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)

COMMON_WARN := -Wall -Wextra -Wpedantic -Werror
USER_CFLAGS := -std=c17 -O2 -g $(COMMON_WARN) -Iinclude -I$(BUILD_DIR) $(LIBBPF_CFLAGS)
USER_LDLIBS := $(LIBBPF_LIBS) -lelf -lz
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -O2 -g -Wall -Werror \
	-I$(BUILD_DIR) -Iinclude

VMLINUX := $(BUILD_DIR)/vmlinux.h
BPF_OBJECT := $(BUILD_DIR)/kernwatch.bpf.o
SKELETON := $(BUILD_DIR)/kernwatch.skel.h
AGENT := $(BUILD_DIR)/kernwatch
FORMAT_TEST := $(BUILD_DIR)/test_format
SAN_TEST := $(BUILD_DIR)/test_format_sanitize

.PHONY: all clean test sanitize verify toolchain-check

all: toolchain-check $(AGENT)

toolchain-check:
	@test -n "$(BPFTOOL)" || (echo "bpftool binary not found; install linux-tools for this distribution" >&2; exit 1)
	@"$(BPFTOOL)" version >/dev/null
	@$(PKG_CONFIG) --exists libbpf

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(VMLINUX): | $(BUILD_DIR)
	test -r /sys/kernel/btf/vmlinux
	"$(BPFTOOL)" btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

$(BPF_OBJECT): bpf/kernwatch.bpf.c include/kernwatch.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKELETON): $(BPF_OBJECT)
	"$(BPFTOOL)" gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR)/main.o: src/main.c include/kernwatch.h include/format.h $(SKELETON)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/format.o: src/format.c include/kernwatch.h include/format.h | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(AGENT): $(BUILD_DIR)/main.o $(BUILD_DIR)/format.o
	$(CC) $^ $(USER_LDLIBS) -o $@

$(FORMAT_TEST): tests/test_format.c src/format.c include/kernwatch.h include/format.h | $(BUILD_DIR)
	$(CC) -std=c17 -O2 -g $(COMMON_WARN) -Iinclude tests/test_format.c src/format.c -o $@

test: $(FORMAT_TEST)
	./$(FORMAT_TEST)

$(SAN_TEST): tests/test_format.c src/format.c include/kernwatch.h include/format.h | $(BUILD_DIR)
	$(SAN_CC) -std=c17 -O1 -g $(COMMON_WARN) -fsanitize=address,undefined \
		-fno-omit-frame-pointer -Iinclude tests/test_format.c src/format.c -o $@

sanitize: $(SAN_TEST)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./$(SAN_TEST)

verify: clean all test sanitize

clean:
	rm -rf $(BUILD_DIR)

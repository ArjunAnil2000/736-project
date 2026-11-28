# Builds the device-aware cache_ext policies in this directory.
# (base_policy_* files are unmodified reference copies of the cache_ext
# policies each one is based on; they are not built here.)
#
# Run on a node booted into the cache_ext kernel (vmlinux.h is generated from
# its BTF), after scripts/setup/install-cache-ext.sh has installed libbpf and
# bpftool:
#
#   make            # all policies, without the debug_* counters
#   make debug      # clean rebuild with the debug_* counters (DEBUG=1)
#   make clean
#
# The debug_* counters (common/hetero_debug.bpf.h) only observe the hooks;
# they never change a policy's decisions. Run `make clean` when switching
# between DEBUG=0 and DEBUG=1: the objects don't record which one built them.
#
# Each policy lives in its own folder as <name>.bpf.c (BPF) + <name>.c
# (loader); the build produces <folder>/<name>.out. Flags follow
# cache_ext/policies/Makefile so results are comparable with the upstream
# policies.

CLANG   ?= clang-14
BPFTOOL ?= /usr/local/sbin/bpftool

CACHE_EXT_POLICIES := ../cache_ext/policies
COMMON             := common

POLICIES := \
	LRU_test/cache_ext_fifo \
	mglru-modified/cache_ext_mglru \
	five-minute-rule/cache_ext_fmr \
	s3-fifo-modified/cache_ext_s4fifo

DEBUG ?= 0

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS = -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c -g -Wall \
	 -I. -I$(COMMON) -I$(CACHE_EXT_POLICIES)
ifeq ($(DEBUG),1)
CFLAGS += -DHETERO_DEBUG
endif
USERSPACE_CFLAGS = -O2 -fsanitize=address -g -Wall -I$(COMMON)
USERSPACE_LINKER_FLAGS = -L/usr/local/lib64 -lbpf -lm

VMLINUX_H = vmlinux.h

# See cache_ext/policies/Makefile: clang's default includes must be added
# explicitly when compiling with -target bpf.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

COMMON_BPF_HDRS  = $(COMMON)/hetero_dev.bpf.h $(COMMON)/hetero_dev_ids.h $(COMMON)/hetero_debug.bpf.h $(COMMON)/hetero_iter.bpf.h
COMMON_USER_HDRS = $(COMMON)/hetero_dev.h $(COMMON)/hetero_dev_ids.h

all: $(addsuffix .out,$(POLICIES))

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

.SECONDARY:
%.bpf.o: %.bpf.c $(VMLINUX_H) $(COMMON_BPF_HDRS)
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) $< -o $@

.SECONDARY:
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

%.out: %.c %.skel.h $(COMMON_USER_HDRS)
	$(CLANG) $(USERSPACE_CFLAGS) $< -o $@ $(USERSPACE_LINKER_FLAGS)

debug:
	$(MAKE) clean
	$(MAKE) DEBUG=1 all

clean:
	rm -f $(VMLINUX_H) \
		$(addsuffix .bpf.o,$(POLICIES)) \
		$(addsuffix .skel.h,$(POLICIES)) \
		$(addsuffix .out,$(POLICIES))

.PHONY: all debug clean

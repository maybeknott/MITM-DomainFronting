# Minimal BPF build for ingress_telemetry.o (Linux + clang/llvm required).
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SOURCES = ingress_telemetry.bpf.c containment_xdp.bpf.c
BPF_OBJECTS = $(BPF_SOURCES:.bpf.c=.o)

all: $(BPF_OBJECTS)

%.o: %.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(BPF_OBJECTS)

.PHONY: all clean

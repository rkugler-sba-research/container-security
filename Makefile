BINARY := env-tracer
BPF_SRC := bpf/env.bpf.c

CLANG ?= clang
GO ?= go

.PHONY: all generate build run clean

all: build

generate: vmlinux.h
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-go-package main \
		-target bpfel \
		bpf $(BPF_SRC) -- -I.

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

build: generate vmlinux.h
	$(GO) build -o $(BINARY) .

run: build
	sudo ./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -f bpf_bpfel.go bpf_bpfeb.go
	rm -f bpf_bpfel.o bpf_bpfeb.o
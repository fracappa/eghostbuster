CLANG ?= clang                                                                                                                                              
CFLAGS := -O2 -g -Wall -Werror
																																							
BPF_SRC := bpf/bpf_eghostbuster.c
BPF_HEADERS := -I./bpf/include
OUTPUT_DIR := pkg/bpf
BINARY := eghostbuster
VMLINUX_H := bpf/include/vmlinux.h

# Default target
.PHONY: all
all: build

.PHONY: vmlinux
vmlinux: $(VMLINUX_H)

# Only regenerate if missing
$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

.PHONY: generate
generate: $(VMLINUX_H)
	go run github.com/cilium/ebpf/cmd/bpf2go \
			-cc $(CLANG) \
			-cflags "$(CFLAGS)" \
			-target amd64 \
			-go-package bpf \
			-output-dir $(OUTPUT_DIR) \
			EGhostBuster $(BPF_SRC) \
			-- $(BPF_HEADERS)

.PHONY: build
build: generate
	CGO_ENABLED=0 go build -o $(BINARY) .

.PHONY: run
run: build
	sudo ./$(BINARY)

.PHONY: clean
clean:
	rm -f $(OUTPUT_DIR)/eghostbuster_*.go
	rm -f $(OUTPUT_DIR)/eghostbuster_*.o
	rm -f $(BINARY)

.PHONY: clean-all
clean-all: clean
	rm -f $(VMLINUX_H)

.PHONY: docker
docker:
	docker build -t eghostbuster:latest .

.PHONY: help
help:
	@echo "Targets:"
	@echo "  build     - Generate BPF and build binary (default)"
	@echo "  generate  - Generate Go code from BPF"
	@echo "  vmlinux   - Generate vmlinux.h"
	@echo "  run       - Build and run with sudo"
	@echo "  docker    - Build Docker image"
	@echo "  clean     - Remove build artifacts"
	@echo "  clean-all - Remove all generated files including vmlinux.h"

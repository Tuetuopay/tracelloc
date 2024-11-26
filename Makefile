CARGO ?= cargo
NIGHTLY ?= +nightly

help:
	@echo "Targets:"
	@echo "    build-ebpf: build eBPF probes"
	@echo "    check-ebpf: run clippy against eBPF probes"

EBPF = ebpf
EBPF_ARGS = --manifest-path $(EBPF)/Cargo.toml --target bpfel-unknown-none -Z build-std=core
EBPF_RSSRC = $(shell find $(EBPF)/src -path $(EBPF)/src/bin -prune -o -name '*.rs' -print) $(shell find ebpf-common/src -name '*.rs')
EBPF_DEPS = $(EBPF)/Cargo.lock $(EBPF)/Cargo.toml $(EBPF)/.cargo/config.toml $(EBPF)/rust-toolchain.toml

$(EBPF)/target/bpfel-unknown-none/release/tracelloc: $(EBPF)/src/main.rs $(EBPF_RSSRC) $(EBPF_DEPS)
	$(CARGO) $(NIGHTLY) build $(EBPF_ARGS) --release

build-ebpf: $(EBPF)/target/bpfel-unknown-none/release/tracelloc
check-ebpf:
	$(CARGO) $(NIGHTLY) clippy $(EBPF_ARGS)
format-ebpf:
	$(CARGO) $(NIGHTLY) fmt --manifest-path $(EBPF)/Cargo.toml

.PHONY: build-ebpf check-ebpf format-ebpf

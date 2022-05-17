.PHONY: all
all: check

.PHONY: check
check:
	cargo +nightly fmt --check
	cargo audit
	cargo clippy
	cargo test
	cargo bench

.PHONY: format
format:
	cargo +nightly fmt

.PHONY: clean
clean:
	cargo clean

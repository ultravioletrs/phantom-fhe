.DEFAULT_GOAL := help

.PHONY: help build test fmt fmt-check clippy doc bench examples check ci clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the workspace
	cargo build --workspace --all-targets

test: ## Run the workspace test suite
	cargo test --workspace --all-targets

fmt: ## Format the workspace
	cargo fmt --all

fmt-check: ## Check formatting without writing changes
	cargo fmt --all -- --check

clippy: ## Lint the workspace, warnings as errors
	cargo clippy --workspace --all-targets --all-features -- -D warnings

doc: ## Build workspace documentation, warnings as errors
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

bench: ## Run the phantom-benches smoke benchmarks
	cargo bench -p phantom-benches

examples: ## Run every phantom-examples binary
	@for example in $$(ls crates/phantom-examples/examples | sed 's/\.rs$$//'); do \
		echo "== $$example =="; \
		cargo run -p phantom-examples --example $$example || exit 1; \
	done

check: fmt-check clippy test doc ## Run the same checks as CI (no bench)

ci: check bench ## Run the full local command matrix, including benches

clean: ## Remove build artifacts
	cargo clean

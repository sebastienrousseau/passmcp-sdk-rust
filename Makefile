# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

PASSMCP_BIN ?= /Users/seb/Code/Public/Go/passmcp/build/passmcp

.PHONY: check test lint reuse family lockstep example conformance

check: test lint reuse family lockstep example conformance

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

reuse:
	reuse lint

family:
	./scripts/family.sh

lockstep:
	./scripts/lockstep.sh

example:
	cargo run --example quickstart

conformance:
	@if [ -x "$(PASSMCP_BIN)" ]; then \
		mkdir -p build; \
		cargo build --example stdio_server; \
		cp target/debug/examples/stdio_server build/stdio_server; \
		"$(PASSMCP_BIN)" check --stdio --rps 0 --samples 2 --concurrency 2 --no-color --output json -- "$(CURDIR)/build/stdio_server" > build/passmcp-report.json; \
		python3 -c 'import json,sys; r=json.load(open("build/passmcp-report.json")); c=r["counts"]; s=r["score"]; print("conformance: score=%s grade=%s pass=%d warn=%d fail=%d" % (s["total"], s["grade"], c["pass"], c["warn"], c["fail"])); sys.exit(0 if c["fail"]==0 and c["warn"]==0 else 1)'; \
	else \
		echo "conformance: skipped ($(PASSMCP_BIN) not found)"; \
	fi

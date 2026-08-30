# /bin/bash does not exist on NixOS — /bin holds only sh.
SHELL := /usr/bin/env bash

.PHONY: proto test

# Refresh the vendored protos from the pin. CI runs the same export and fails on
# any difference (D70), so this is the only sanctioned way to change proto/.
proto:
	@rm -rf proto
	@buf export "https://github.com/yadgarhq/proto.git#tag=$$(tr -d '[:space:]' < PROTO_VERSION)" \
		$$(grep -v '^\s*#' PROTO_PATHS | grep -v '^\s*$$' | sed 's/^/--path /') \
		-o proto
	@echo "proto/ refreshed from $$(cat PROTO_VERSION)"

test:
	cargo test --all-features

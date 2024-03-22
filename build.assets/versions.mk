# Keep all tool versions in one place.
# This file can be included in other Makefiles to avoid duplication.

GOLANG_VERSION ?= go1.21.8
GOLANGCI_LINT_VERSION ?= v1.57.1

NODE_VERSION ?= 20.11.1

# Run lint-rust check locally before merging code after you bump this.
RUST_VERSION ?= 1.71.1
LIBBPF_VERSION ?= 1.2.2
LIBPCSCLITE_VERSION ?= 1.9.9-teleport

DEVTOOLSET ?= devtoolset-12

# Protogen related versions.
BUF_VERSION ?= v1.30.0
# Keep in sync with api/proto/buf.yaml (and buf.lock).
GOGO_PROTO_TAG ?= v1.3.2
NODE_GRPC_TOOLS_VERSION ?= 1.12.4
NODE_PROTOC_TS_VERSION ?= 5.0.1
PROTOC_VER ?= 3.20.3

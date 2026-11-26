# SPDX-License-Identifier: Apache-2.0

GO            ?= go
export GOTOOLCHAIN ?= local
BPF_MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null || echo x86_64-linux-gnu)
export BPF_MULTIARCH
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0-dev)
LDFLAGS       := -s -w -X github.com/tsuzu/xdpl2/internal/version.Version=$(VERSION)
BIN           := bin
IMAGE         ?= ghcr.io/tsuzu/xdpl2:$(VERSION)

BPF_SRC := bpf/xdpl2.bpf.c bpf/xdpl2.h
BPF_GEN := internal/bpfobj/xdpl2_bpfel.go internal/bpfobj/xdpl2_bpfel.o

.PHONY: all generate build test vet fmt-check unit integration lint-manifests image clean

all: build

$(BPF_GEN): $(BPF_SRC) internal/bpfobj/gen.go
	$(GO) generate ./internal/bpfobj/

generate: $(BPF_GEN)

build: generate
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/host-local github.com/containernetworking/plugins/plugins/ipam/host-local

vet: generate
	$(GO) vet ./...

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go' 2>/dev/null || find . -name '*.go')); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

unit: generate
	$(GO) test -race -count=1 ./...

test: vet fmt-check unit

# Needs root (network namespaces, XDP). Regenerates TESTLOG.md.
integration: build
	test/netns_test.sh --testlog TESTLOG.md

lint-manifests:
	kubeconform -strict -summary -ignore-missing-schemas deploy/*.yaml

image:
	docker build -t $(IMAGE) --build-arg VERSION=$(VERSION) .

clean:
	rm -rf $(BIN) $(BPF_GEN)

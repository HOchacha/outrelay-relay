# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

# OutRelay relay (data plane).
# Common targets: build / test / gofmt / golangci-lint / gosec /
# build-image / push-image / clean. See `make help`.

# === Overridable variables ============================================
IMAGE_NAME     ?= outrelay-relay
IMAGE          ?= docker.io/boanlab/$(IMAGE_NAME)
TAG            ?= v0.1.0

GO             ?= go
DOCKER         ?= docker
BIN_DIR        ?= bin

# LDFLAGS strip debug info and stamp the build's version into the
# `main.Version` symbol of the binary. `make TAG=v1.2.3` => version
# string baked at link time; the default is the TAG above.
LDFLAGS        ?= -s -w -X main.Version=$(TAG)
GO_BUILD       ?= CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)'

# Make sure tools we install via `go install` are reachable in the
# same Make invocation: prepend GOBIN (or $GOPATH/bin) to PATH.
GOBIN          ?= $(shell $(GO) env GOBIN)
ifeq ($(GOBIN),)
GOBIN          := $(shell $(GO) env GOPATH)/bin
endif
export PATH    := $(GOBIN):$(PATH)

.PHONY: help build test gofmt golangci-lint gosec build-image push-image clean

.DEFAULT_GOAL := build

help: ## show this help
	@awk 'BEGIN{FS=":.*##"; printf "Targets:\n"} \
	     /^[a-zA-Z][a-zA-Z0-9_-]*:.*##/ { \
	       printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 \
	     }' $(MAKEFILE_LIST)

# === Build ============================================================

build: gofmt golangci-lint gosec ## quality gates + compile binary to ./bin/
	$(GO_BUILD) -o $(BIN_DIR)/outrelay-relay ./cmd/outrelay-relay

# === Quality gates ====================================================

gofmt: ## fail on gofmt drift (use `gofmt -w .` to fix)
	@drift=$$(gofmt -l . 2>&1); \
	if [ -n "$$drift" ]; then \
	  echo "files with gofmt drift:"; echo "$$drift"; \
	  gofmt -d .; \
	  exit 1; \
	fi

golangci-lint: ## golangci-lint run ./... (auto-installs if missing)
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
	  echo "installing golangci-lint into $(GOBIN) ..."; \
	  $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
	fi
	golangci-lint run ./...

gosec: ## gosec security scan (auto-installs if missing)
	@if ! command -v gosec >/dev/null 2>&1; then \
	  echo "installing gosec into $(GOBIN) ..."; \
	  $(GO) install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	gosec -quiet -exclude-generated ./...

test: ## go test -race -count=1 ./...
	$(GO) test -race -count=1 ./...

# === Container image ==================================================

build-image: ## docker build -> $(IMAGE):$(TAG) and $(IMAGE):latest
	$(DOCKER) build -f $(CURDIR)/Dockerfile \
	  -t $(IMAGE):$(TAG) -t $(IMAGE):latest \
	  --build-arg VERSION=$(TAG) $(CURDIR)/..

push-image: build-image ## docker push both $(TAG) and latest
	$(DOCKER) push $(IMAGE):$(TAG)
	$(DOCKER) push $(IMAGE):latest

# === Cleanup ==========================================================

clean: ## rm bin/ dist/
	rm -rf $(BIN_DIR)/ dist/

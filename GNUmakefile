GO ?= go
GOFMT ?= gofmt

GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build check fmt fmt-check test test-race vet

all: check build

build:
	$(GO) build ./...

check: fmt-check vet test

fmt:
	$(GOFMT) -w $(GO_FILES)

fmt-check:
	@test -z "$$($(GOFMT) -l $(GO_FILES))"

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

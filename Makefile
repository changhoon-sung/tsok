SHELL := /bin/sh

GO ?= go
DIST_DIR ?= dist
VERSION ?= dev
PACKAGE := ./cmd/tsok
BINARY := tsok
BUILD_DIR := $(DIST_DIR)/build

COMMIT ?= $(shell git rev-parse HEAD)
COMMIT_DATE ?= $(shell git show -s --format=%ct HEAD)
HOST_GOOS := $(shell $(GO) env GOOS)
HOST_GOARCH := $(shell $(GO) env GOARCH)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.commitDate=$(COMMIT_DATE)

.DEFAULT_GOAL := build

.PHONY: build linux linux-amd64 linux-arm64 darwin darwin-amd64 darwin-arm64 release-builds test

build:
	@mkdir -p "$(DIST_DIR)"
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$(DIST_DIR)/$(BINARY)" $(PACKAGE)

linux: linux-amd64 linux-arm64

linux-amd64:
	@mkdir -p "$(BUILD_DIR)/linux_amd64"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$(BUILD_DIR)/linux_amd64/$(BINARY)" $(PACKAGE)
	tar -C "$(BUILD_DIR)/linux_amd64" -czf "$(DIST_DIR)/tsok_linux_amd64.tar.gz" "$(BINARY)"

linux-arm64:
	@mkdir -p "$(BUILD_DIR)/linux_arm64"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$(BUILD_DIR)/linux_arm64/$(BINARY)" $(PACKAGE)
	tar -C "$(BUILD_DIR)/linux_arm64" -czf "$(DIST_DIR)/tsok_linux_arm64.tar.gz" "$(BINARY)"

darwin: darwin-amd64 darwin-arm64

darwin-amd64:
	@mkdir -p "$(BUILD_DIR)/darwin_amd64"
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$(BUILD_DIR)/darwin_amd64/$(BINARY)" $(PACKAGE)
	tar -C "$(BUILD_DIR)/darwin_amd64" -czf "$(DIST_DIR)/tsok_darwin_amd64.tar.gz" "$(BINARY)"

darwin-arm64:
	@mkdir -p "$(BUILD_DIR)/darwin_arm64"
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$(BUILD_DIR)/darwin_arm64/$(BINARY)" $(PACKAGE)
	tar -C "$(BUILD_DIR)/darwin_arm64" -czf "$(DIST_DIR)/tsok_darwin_arm64.tar.gz" "$(BINARY)"

release-builds: linux darwin

test:
	$(GO) test -race ./...

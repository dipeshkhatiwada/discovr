BINARY   ?= discovr
DIST     ?= dist
PKG      ?= ./cmd/$(BINARY)
GOFLAGS  ?= -trimpath
TAGS     ?=
LDFLAGS  ?=

PLATFORMS := \
	macos:darwin/amd64 \
	macos:darwin/arm64 \
	linux:linux/amd64 \
	linux:linux/arm64 \
	windows:windows/amd64 \
	windows:windows/arm64

.PHONY: build all build-mac build-linux build-windows cross tidy clean help

build: ## Build for the current platform
	@mkdir -p $(DIST)
	GOFLAGS="$(GOFLAGS)" go build -tags "$(TAGS)" -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(PKG)
	@echo "Built $(DIST)/$(BINARY)"

build-mac: ## Cross-compile macOS binaries (amd64 + arm64)
	$(MAKE) cross GO_TARGET=macos

build-linux: ## Cross-compile Linux binaries (amd64 + arm64)
	$(MAKE) cross GO_TARGET=linux

build-windows: ## Cross-compile Windows binaries (amd64 + arm64)
	$(MAKE) cross GO_TARGET=windows

all: build-mac build-linux build-windows ## Build for macOS, Linux, and Windows

cross: ## Cross-compile for platforms in $(PLATFORMS)
	@mkdir -p $(DIST)
	@set -e; \
	for entry in $(PLATFORMS); do \
		target=$${entry%%:*}; \
		pair=$${entry#*:}; \
		if [ -n "$(GO_TARGET)" ] && [ "$$target" != "$(GO_TARGET)" ]; then \
			continue; \
		fi; \
		GOOS=$${pair%/*}; \
		GOARCH=$${pair#*/}; \
		EXT=""; \
		[ "$$GOOS" = "windows" ] && EXT=".exe"; \
		OUT="$(DIST)/$(BINARY)-$$GOOS-$$GOARCH$$EXT"; \
		echo "Building $$OUT"; \
		GOOS=$$GOOS GOARCH=$$GOARCH CGO_ENABLED=0 GOFLAGS="$(GOFLAGS)" \
			go build -tags "$(TAGS)" -ldflags "$(LDFLAGS)" -o "$$OUT" $(PKG); \
	done
	@echo "Artifacts saved to $(DIST)/"

tidy: ## Sync dependencies
	go mod tidy

clean: ## Remove build artifacts
	rm -rf $(DIST)
	@echo "Cleaned $(DIST)/"

help: ## Show available targets and descriptions
	@grep -E '^[a-zA-Z_-]+:.*##' Makefile | while read -r line; do \
		target=$$(echo $$line | cut -d':' -f1); \
		desc=$$(echo $$line | sed -E 's/^[^#]+##\s*//'); \
		printf "%-15s %s\n" $$target "$$desc"; \
	done

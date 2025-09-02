BINARY := discovr
DIST   := dist

# List of target OS/ARCH pairs to cross-compile
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: build cross clean tidy

build: ## Build for the current platform into dist/
	@mkdir -p $(DIST)
	go build -o $(DIST)/$(BINARY) .
	@echo "Built $(DIST)/$(BINARY)"

cross: ## Cross-compile for multiple OS/ARCH into dist/
	@mkdir -p $(DIST)
	@set -e; \
	for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*}; \
		GOARCH=$${platform#*/}; \
		EXT=""; \
		[ "$$GOOS" = "windows" ] && EXT=".exe"; \
		OUT="$(DIST)/$(BINARY)-$$GOOS-$$GOARCH$$EXT"; \
		echo "Building $$OUT"; \
		GOOS=$$GOOS GOARCH=$$GOARCH CGO_ENABLED=0 go build -o "$$OUT" .; \
	done
	@echo "Artifacts in $(DIST)/"

tidy: ## Sync go.mod/go.sum
	go mod tidy

clean: ## Remove build artifacts
	rm -rf $(DIST)
	@echo "Cleaned $(DIST)/"


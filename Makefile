BINARY   := pxgo
MODULE   := github.com/pavelsimo/pxgo
BUILD_DIR := bin
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -ldflags "-s -w -X main.version=$(VERSION)"

GOLANGCI_LINT_VERSION := v2.12.2
GOFUMPT_VERSION       := v0.7.0
GOIMPORTS_VERSION     := v0.29.0

.PHONY: build install test coverage lint fmt fmt-check ci release clean tools docs help

build: ## Build binary to bin/
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) .

install: ## Install binary to $GOPATH/bin
	go install $(LDFLAGS) .

test: ## Run tests with race detector and coverage
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

coverage: test ## Open coverage report in browser
	go tool cover -html=coverage.out

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code with gofumpt and goimports
	gofumpt -w .
	goimports -w .

fmt-check: ## Check formatting (exits 1 if dirty, for CI)
	@out=$$(gofumpt -l .); if [ -n "$$out" ]; then echo "gofumpt: $$out"; exit 1; fi
	@out=$$(goimports -l .); if [ -n "$$out" ]; then echo "goimports: $$out"; exit 1; fi

ci: fmt-check lint test build ## Full CI gate: fmt-check + lint + test + build

release: ## Cut a release with goreleaser (requires GITHUB_TOKEN)
	goreleaser release --clean

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)/ dist/ coverage.out

tools: ## Install dev tools
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/evilmartians/lefthook@latest

docs: ## Build documentation site
	node scripts/build-docs-site.mjs

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

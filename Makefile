BINARY      := dockgate
PKG         := ./cmd/dockgate
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)

.PHONY: all build test race vet fmt lint cover run clean docker tidy

all: vet test build

build: ## Build the dockgate binary into ./bin
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test: ## Run all tests
	go test ./...

race: ## Run tests with the race detector
	go test -race ./...

cover: ## Run tests and print a coverage summary
	go test -coverprofile=coverage.txt ./...
	go tool cover -func=coverage.txt | tail -n 1

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -s -w .

tidy: ## Tidy module dependencies
	go mod tidy

run: build ## Build and run against the local Docker socket on 127.0.0.1:2375
	./bin/$(BINARY) --policy ./policy.yaml

docker: ## Build the Docker image
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

clean: ## Remove build artifacts
	rm -rf bin dist coverage.txt

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

.PHONY: all build clean run-gateway run-client certs test lint docker-build docker-run package build-all help

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# Go build settings
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED ?= 0

# Binary names
GATEWAY_BINARY = anyproxy-gateway
CLIENT_BINARY = anyproxy-client

# Build directory
BUILD_DIR = bin
PACKAGE_DIR = build

all: certs build ## Build everything

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build binaries for current platform
	@echo "Building for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(GATEWAY_BINARY) cmd/gateway/main.go
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(CLIENT_BINARY) cmd/client/main.go
	@echo "Build completed: $(BUILD_DIR)/$(GATEWAY_BINARY), $(BUILD_DIR)/$(CLIENT_BINARY)"

build-all: ## Build binaries for all platforms
	@echo "Building for all platforms..."
	@mkdir -p $(PACKAGE_DIR)
	
	# Linux AMD64
	@echo "Building for linux/amd64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(GATEWAY_BINARY)-linux-amd64 cmd/gateway/main.go
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(CLIENT_BINARY)-linux-amd64 cmd/client/main.go
	
	# Linux ARM64
	@echo "Building for linux/arm64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(GATEWAY_BINARY)-linux-arm64 cmd/gateway/main.go
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(CLIENT_BINARY)-linux-arm64 cmd/client/main.go
	
	# Windows AMD64
	@echo "Building for windows/amd64..."
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(GATEWAY_BINARY)-windows-amd64.exe cmd/gateway/main.go
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(CLIENT_BINARY)-windows-amd64.exe cmd/client/main.go
	
	# macOS AMD64
	@echo "Building for darwin/amd64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(GATEWAY_BINARY)-darwin-amd64 cmd/gateway/main.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(CLIENT_BINARY)-darwin-amd64 cmd/client/main.go
	
	# macOS ARM64
	@echo "Building for darwin/arm64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(GATEWAY_BINARY)-darwin-arm64 cmd/gateway/main.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(PACKAGE_DIR)/$(CLIENT_BINARY)-darwin-arm64 cmd/client/main.go
	
	@echo "Cross-compilation completed. Binaries are in $(PACKAGE_DIR)/"

certs: ## Generate TLS certificates
	@echo "Generating TLS certificates..."
	@bash scripts/generate_certs.sh
	@echo "Certificates generated in certs/ directory"

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "Tests completed"

test-coverage: test ## Run tests with coverage report
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint: ## Run linter
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install it from https://golangci-lint.run/usage/install/" && exit 1)
	@golangci-lint run --timeout=5m
	@echo "Linting completed"

run-gateway: build ## Run gateway
	@echo "Starting gateway..."
	@./$(BUILD_DIR)/$(GATEWAY_BINARY) --config configs/config.yaml

run-client: build ## Run client
	@echo "Starting client..."
	@./$(BUILD_DIR)/$(CLIENT_BINARY) --config configs/config.yaml

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t anyproxy:$(VERSION) \
		-t anyproxy:latest .
	@echo "Docker image built: anyproxy:$(VERSION)"

docker-run: docker-build ## Run with Docker Compose
	@echo "Starting services with Docker Compose..."
	@VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_TIME=$(BUILD_TIME) docker-compose up -d
	@echo "Services started. Use 'docker-compose logs -f' to view logs"

docker-stop: ## Stop Docker Compose services
	@echo "Stopping Docker Compose services..."
	@docker-compose down
	@echo "Services stopped"

docker-logs: ## View Docker Compose logs
	@docker-compose logs -f

package: build ## Create release package
	@echo "Creating release package..."
	@mkdir -p $(PACKAGE_DIR)
	@tar -zcf $(PACKAGE_DIR)/anyproxy-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz \
		-C $(BUILD_DIR) $(GATEWAY_BINARY) $(CLIENT_BINARY) \
		-C .. certs/ configs/config.yaml README.md CHANGELOG.md
	@echo "Package created: $(PACKAGE_DIR)/anyproxy-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz"

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(PACKAGE_DIR) coverage.out coverage.html
	@docker-compose down --volumes --remove-orphans 2>/dev/null || true
	@echo "Clean completed"

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Development tools installed"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify
	@echo "Dependencies downloaded"

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@echo "Code formatted"

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...
	@echo "go vet completed"

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

release: clean check build-all package ## Prepare release (clean, check, build-all, package)

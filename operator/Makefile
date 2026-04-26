BINARY     := warden-operator
BUILD_DIR  := bin
GOFLAGS    := -trimpath
LDFLAGS    := -s -w

CONTROLLER_GEN := $(shell which controller-gen 2>/dev/null)
ENVTEST        := $(shell which setup-envtest 2>/dev/null)

.PHONY: all build release test test-race lint vet clean generate manifests fmt help

all: deps lint test build ## Full pipeline: deps → lint → test → build

build: fmt vet ## Build operator binary
	go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/operator

release: fmt vet ## Release build: stripped, static, CGO_ENABLED=0
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/operator

test: generate fmt vet ## Run tests
	go test ./... -count=1

test-race: generate fmt vet ## Run tests with race detector
	go test ./... -count=1 -race

fuzz: ## Run fuzz tests
	@echo "==> Discovering fuzz targets..."
	@TARGETS=$$(grep -r 'func Fuzz' --include='*_test.go' -l . 2>/dev/null); \
	if [ -z "$$TARGETS" ]; then echo "No fuzz targets found"; exit 0; fi; \
	for f in $$TARGETS; do \
		PKG=$$(dirname $$f); \
		FUNCS=$$(grep -oP 'func (Fuzz\w+)' $$f | awk '{print $$2}'); \
		for fn in $$FUNCS; do \
			echo "==> Fuzzing $$fn in $$PKG ($(FUZZ_TIME))"; \
			go test $$PKG -fuzz=$$fn -fuzztime=$${FUZZ_TIME:-30s} || exit 1; \
		done; \
	done

lint: vet ## Lint
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not found, skipping"; \
	fi

vet: ## Run go vet
	go vet ./...

fmt: ## Run gofmt
	gofmt -w .

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

deps: ## Download dependencies
	go mod download
	go mod tidy

generate: controller-gen ## Generate deepcopy code
	$(CONTROLLER_GEN) object paths="./api/..."

manifests: controller-gen ## Generate CRD and RBAC manifests
	$(CONTROLLER_GEN) crd rbac:roleName=warden-operator paths="./..." output:crd:artifacts:config=config/crd/bases

controller-gen: ## Install controller-gen if missing
	@if ! command -v controller-gen >/dev/null 2>&1; then \
		echo "Installing controller-gen..."; \
		go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest; \
	fi

envtest: ## Install setup-envtest if missing
	@if ! command -v setup-envtest >/dev/null 2>&1; then \
		echo "Installing setup-envtest..."; \
		go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest; \
	fi

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

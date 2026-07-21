# Self-documented Makefile (https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html)
# Run 'make' or 'make help' to list targets.

.DEFAULT_GOAL := help

REGISTRY     ?= ghcr.io/otfabric
VERSION      ?= dev
PLATFORMS    ?= linux/amd64,linux/arm64

IMAGE_OPEN62541 = $(REGISTRY)/opcua-interop-open62541
IMAGE_MILO      = $(REGISTRY)/opcua-interop-milo

OPEN62541_PORT ?= 4840
MILO_PORT      ?= 4841

FIXTURE_SCHEMA = fixtures/schema/opcua-fixture.schema.json
FIXTURE_DIRS   = $(wildcard fixtures/*/fixture.json)

.PHONY: help all build build-open62541 build-milo image-open62541 image-milo validate validate-fixtures run-open62541 run-milo smoke smoke-open62541 smoke-milo smoke-cross-stack certs release clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: validate build ## Run all targets

# ── Build ────────────────────────────────────────────────────────────────────

build: build-open62541 build-milo ## Build both adapter images (multi-arch)

build-open62541: ## Build open62541 image only
	@echo "Building open62541 image..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--file open62541/Dockerfile \
		open62541/

build-milo: ## Build Milo image only
	@echo "Building Milo image..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_MILO):$(VERSION) \
		--file milo/Dockerfile \
		milo/

image-open62541: ## Build open62541 image (host arch)
	@echo "Building open62541 image (host arch)..."
	docker build \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--file open62541/Dockerfile \
		open62541/

image-milo: ## Build Milo image (host arch)
	@echo "Building Milo image (host arch)..."
	docker build \
		--tag $(IMAGE_MILO):$(VERSION) \
		--file milo/Dockerfile \
		milo/

# ── Validation ───────────────────────────────────────────────────────────────

validate: validate-fixtures ## Run all validation checks

validate-fixtures: ## Validate all fixture files against schema
	@echo "Validating fixture files..."
	@scripts/validate-fixtures.sh

# ── Run ──────────────────────────────────────────────────────────────────────

run-open62541: ## Start open62541 server on port $(OPEN62541_PORT)
	@echo "Starting open62541 server on port $(OPEN62541_PORT)..."
	docker run --rm \
		-p $(OPEN62541_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		-v "$(PWD)/certs/test-pki:/pki:ro" \
		$(IMAGE_OPEN62541):$(VERSION) \
		server \
		--fixture /fixtures/baseline/fixture.json \
		--endpoint opc.tcp://0.0.0.0:4840/opcua-interop \
		--pki-dir /pki \
		--ready-file /run/opcua-interop/ready

run-milo: ## Start Milo server on port $(MILO_PORT)
	@echo "Starting Milo server on port $(MILO_PORT)..."
	docker run --rm \
		-p $(MILO_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		-v "$(PWD)/certs/test-pki:/pki:ro" \
		$(IMAGE_MILO):$(VERSION) \
		server \
		--fixture /fixtures/baseline/fixture.json \
		--endpoint opc.tcp://0.0.0.0:4840/opcua-interop \
		--pki-dir /pki \
		--ready-file /run/opcua-interop/ready

# ── Smoke tests ──────────────────────────────────────────────────────────────

smoke: smoke-open62541 smoke-milo smoke-cross-stack ## Run all smoke tests

smoke-open62541: ## Smoke test open62541 adapter
	@echo "Smoking open62541 adapter..."
	@scripts/smoke.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

smoke-milo: ## Smoke test Milo adapter
	@echo "Smoking Milo adapter..."
	@scripts/smoke.sh milo $(IMAGE_MILO):$(VERSION)

smoke-cross-stack: ## Cross-stack interop self-check
	@echo "Smoking cross-stack interop self-check..."
	@scripts/smoke.sh cross $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION)

# ── Certificates ─────────────────────────────────────────────────────────────

certs: ## Generate test PKI
	@echo "Generating test PKI..."
	@certs/generate.sh

# ── Release ──────────────────────────────────────────────────────────────────

release: ## Build and push multi-arch release images
	@echo "Building and pushing multi-arch release images..."
ifndef VERSION
	$(error VERSION is required: make release VERSION=v0.1.0)
endif
	@if ! echo "$(VERSION)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "Error: VERSION must be in the form v<major>.<minor>.<patch>"; exit 1; fi
	$(eval MAJOR := $(shell echo $(VERSION) | cut -d. -f1 | tr -d v))
	$(eval MINOR := $(shell echo $(VERSION) | cut -d. -f1-2 | tr -d v))
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--tag $(IMAGE_OPEN62541):$(MINOR) \
		--tag $(IMAGE_OPEN62541):$(MAJOR) \
		--file open62541/Dockerfile \
		open62541/
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_MILO):$(VERSION) \
		--tag $(IMAGE_MILO):$(MINOR) \
		--tag $(IMAGE_MILO):$(MAJOR) \
		--file milo/Dockerfile \
		milo/
	@echo "Released $(VERSION)"

# ── Clean ────────────────────────────────────────────────────────────────────

clean: ## Remove containers and build artifacts
	@echo "Removing containers and build artifacts..."
	docker compose down --remove-orphans 2>/dev/null || true
	docker rmi $(IMAGE_OPEN62541):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_MILO):$(VERSION) 2>/dev/null || true
	rm -rf open62541/build/ milo/target/


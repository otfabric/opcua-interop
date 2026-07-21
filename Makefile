# Self-documented Makefile (https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html)
# Run 'make' or 'make help' to list targets.
#
# Pre-push gate:  make ci
# Quick smoke:    make image smoke

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

.PHONY: help all ci \
        image image-open62541 image-milo \
        buildx buildx-open62541 buildx-milo \
        validate validate-fixtures \
        test test-open62541 test-milo \
        smoke smoke-open62541 smoke-milo smoke-cross-stack \
        shutdown shutdown-open62541 shutdown-milo \
        run-open62541 run-milo \
        certs release clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-26s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: validate image ## Validate fixtures and build local images

# ── Full local CI (mirrors GitHub Actions) ────────────────────────────────────

ci: validate image test smoke shutdown ## Full local CI: validate → build → unit-test → smoke → shutdown
	@echo ""
	@echo "✓ All local CI checks passed."

# ── Local single-arch images (loaded into Docker, used for smoke/dev) ─────────

image: image-open62541 image-milo ## Build both images for host architecture

image-open62541: ## Build open62541 image (host arch, loaded into Docker)
	@echo "Building open62541 image (host arch)..."
	docker build \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--file open62541/Dockerfile \
		open62541/

image-milo: ## Build Milo image (host arch, loaded into Docker)
	@echo "Building Milo image (host arch)..."
	docker build \
		--tag $(IMAGE_MILO):$(VERSION) \
		--file milo/Dockerfile \
		milo/

# ── Multi-arch buildx (pushes to registry; requires --push or --output) ───────

buildx: buildx-open62541 buildx-milo ## Build and push both images (multi-arch)

buildx-open62541: ## Build and push open62541 image (multi-arch)
	@echo "Building open62541 image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--file open62541/Dockerfile \
		open62541/

buildx-milo: ## Build and push Milo image (multi-arch)
	@echo "Building Milo image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_MILO):$(VERSION) \
		--file milo/Dockerfile \
		milo/

# ── Validation ───────────────────────────────────────────────────────────────

validate: validate-fixtures ## Run all validation checks

validate-fixtures: ## Validate all fixture files against schema
	@echo "Validating fixture files..."
	@scripts/validate-fixtures.sh

# ── Unit tests (requires images to be built) ──────────────────────────────────

test: test-open62541 test-milo ## Run unit tests for both adapters

test-open62541: image-open62541 ## Build open62541 image and run unit tests
	@echo "Running open62541 unit tests..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_OPEN62541):$(VERSION) \
		test

test-milo: image-milo ## Build Milo image and run unit tests
	@echo "Running Milo unit tests..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_MILO):$(VERSION) \
		test

# ── Smoke tests ──────────────────────────────────────────────────────────────

smoke: smoke-open62541 smoke-milo smoke-cross-stack ## Run all smoke tests (images must be built)

smoke-open62541: ## Smoke test open62541 adapter (run 'make image-open62541' first)
	@echo "Smoking open62541 adapter..."
	@scripts/smoke.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

smoke-milo: ## Smoke test Milo adapter (run 'make image-milo' first)
	@echo "Smoking Milo adapter..."
	@scripts/smoke.sh milo $(IMAGE_MILO):$(VERSION)

smoke-cross-stack: ## Cross-stack interop self-check (run 'make image' first)
	@echo "Smoking cross-stack interop self-check..."
	@scripts/smoke.sh cross $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION)

# ── Graceful shutdown tests ───────────────────────────────────────────────────

shutdown: shutdown-open62541 shutdown-milo ## Test graceful shutdown for both adapters

shutdown-open62541: ## Test open62541 graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing open62541 graceful shutdown..."
	@scripts/shutdown-test.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

shutdown-milo: ## Test Milo graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing Milo graceful shutdown..."
	@scripts/shutdown-test.sh milo $(IMAGE_MILO):$(VERSION)

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
		--advertised-host localhost \
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
		--advertised-host localhost \
		--pki-dir /pki \
		--ready-file /run/opcua-interop/ready

# ── Certificates ─────────────────────────────────────────────────────────────

certs: ## Generate test PKI
	@echo "Generating test PKI..."
	@certs/generate.sh

# ── Release ──────────────────────────────────────────────────────────────────

release: ## Build and push multi-arch release images (requires VERSION=v0.x.x)
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

clean: ## Remove containers and local build artifacts
	@echo "Removing containers and build artifacts..."
	docker compose down --remove-orphans 2>/dev/null || true
	docker rmi $(IMAGE_OPEN62541):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_MILO):$(VERSION) 2>/dev/null || true
	rm -rf open62541/build/ milo/target/

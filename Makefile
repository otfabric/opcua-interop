REGISTRY     ?= ghcr.io/otfabric
VERSION      ?= dev
PLATFORMS    ?= linux/amd64,linux/arm64

IMAGE_OPEN62541 = $(REGISTRY)/opcua-interop-open62541
IMAGE_MILO      = $(REGISTRY)/opcua-interop-milo

OPEN62541_PORT ?= 4840
MILO_PORT      ?= 4841

FIXTURE_SCHEMA = fixtures/schema/opcua-fixture.schema.json
FIXTURE_DIRS   = $(wildcard fixtures/*/fixture.json)

.PHONY: all
all: validate build

# ── Build ────────────────────────────────────────────────────────────────────

.PHONY: build
build: build-open62541 build-milo

.PHONY: build-open62541
build-open62541:
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--file open62541/Dockerfile \
		open62541/

.PHONY: build-milo
build-milo:
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_MILO):$(VERSION) \
		--file milo/Dockerfile \
		milo/

.PHONY: image-open62541
image-open62541:
	docker build \
		--tag $(IMAGE_OPEN62541):$(VERSION) \
		--file open62541/Dockerfile \
		open62541/

.PHONY: image-milo
image-milo:
	docker build \
		--tag $(IMAGE_MILO):$(VERSION) \
		--file milo/Dockerfile \
		milo/

# ── Validation ───────────────────────────────────────────────────────────────

.PHONY: validate
validate: validate-fixtures

.PHONY: validate-fixtures
validate-fixtures:
	@scripts/validate-fixtures.sh

# ── Run ──────────────────────────────────────────────────────────────────────

.PHONY: run-open62541
run-open62541:
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

.PHONY: run-milo
run-milo:
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

.PHONY: smoke
smoke: smoke-open62541 smoke-milo smoke-cross-stack

.PHONY: smoke-open62541
smoke-open62541:
	@scripts/smoke.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

.PHONY: smoke-milo
smoke-milo:
	@scripts/smoke.sh milo $(IMAGE_MILO):$(VERSION)

.PHONY: smoke-cross-stack
smoke-cross-stack:
	@scripts/smoke.sh cross $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION)

# ── Certificates ─────────────────────────────────────────────────────────────

.PHONY: certs
certs:
	@certs/generate.sh

# ── Release ──────────────────────────────────────────────────────────────────

.PHONY: release
release:
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

.PHONY: clean
clean:
	docker compose down --remove-orphans 2>/dev/null || true
	docker rmi $(IMAGE_OPEN62541):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_MILO):$(VERSION) 2>/dev/null || true
	rm -rf open62541/build/ milo/target/

.PHONY: help
help:
	@echo "Usage: make [target] [VERSION=v0.1.0]"
	@echo ""
	@echo "Build:"
	@echo "  build                Build both adapter images (multi-arch)"
	@echo "  build-open62541      Build open62541 image only"
	@echo "  build-milo           Build Milo image only"
	@echo "  image-open62541      Build open62541 image (host arch)"
	@echo "  image-milo           Build Milo image (host arch)"
	@echo ""
	@echo "Validation:"
	@echo "  validate             Run all validation checks"
	@echo "  validate-fixtures    Validate all fixture files against schema"
	@echo ""
	@echo "Run:"
	@echo "  run-open62541        Start open62541 server on port $(OPEN62541_PORT)"
	@echo "  run-milo             Start Milo server on port $(MILO_PORT)"
	@echo ""
	@echo "Smoke tests:"
	@echo "  smoke                Run all smoke tests"
	@echo "  smoke-open62541      Smoke test open62541 adapter"
	@echo "  smoke-milo           Smoke test Milo adapter"
	@echo "  smoke-cross-stack    Cross-stack interop self-check"
	@echo ""
	@echo "Other:"
	@echo "  certs                Generate test PKI"
	@echo "  release VERSION=...  Build and push multi-arch release images"
	@echo "  clean                Remove containers and build artifacts"

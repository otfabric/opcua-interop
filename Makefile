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
MQTT_PORT      ?= 1883

# MQTT broker for the PubSub tests (multi-arch index digest of eclipse-mosquitto:2.0.22)
MOSQUITTO_IMAGE ?= eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c

FIXTURE_SCHEMA = fixtures/schema/opcua-fixture.schema.json
FIXTURE_DIRS   = $(wildcard fixtures/*/fixture.json)

.PHONY: help all ci \
        image image-open62541 image-milo \
        buildx buildx-open62541 buildx-milo \
        validate validate-fixtures \
        test test-open62541 test-milo \
        smoke smoke-open62541 smoke-milo smoke-cross-stack smoke-pubsub \
        shutdown shutdown-open62541 shutdown-milo \
        run-open62541 run-milo run-mosquitto \
        certs check-release release-notes publish publish-arch publish-manifest digests clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-26s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: validate image ## Validate fixtures and build local images

# ── Full local CI (mirrors GitHub Actions) ────────────────────────────────────

ci: validate image test smoke shutdown ## Full local CI: validate → build → unit-test → smoke (incl. PubSub) → shutdown
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

smoke: smoke-open62541 smoke-milo smoke-cross-stack smoke-pubsub ## Run all smoke tests (images must be built)

smoke-open62541: ## Smoke test open62541 adapter (run 'make image-open62541' first)
	@echo "Smoking open62541 adapter..."
	@scripts/smoke.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

smoke-milo: ## Smoke test Milo adapter (run 'make image-milo' first)
	@echo "Smoking Milo adapter..."
	@scripts/smoke.sh milo $(IMAGE_MILO):$(VERSION)

smoke-cross-stack: ## Cross-stack interop self-check (run 'make image' first)
	@echo "Smoking cross-stack interop self-check..."
	@scripts/smoke.sh cross $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION)

smoke-pubsub: ## PubSub smoke: UDP / MQTT / security / SKS / codec / information model (open62541)
	@echo "Smoking PubSub (open62541)..."
	@scripts/pubsub-smoke.sh $(IMAGE_OPEN62541):$(VERSION)

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

run-mosquitto: ## Start the MQTT broker for PubSub tests on port $(MQTT_PORT)
	@echo "Starting Eclipse Mosquitto on port $(MQTT_PORT)..."
	docker run --rm \
		-p $(MQTT_PORT):1883 \
		-v "$(PWD)/mqtt/mosquitto.conf:/mosquitto-interop.conf:ro" \
		$(MOSQUITTO_IMAGE) \
		mosquitto -c /mosquitto-interop.conf

# ── Certificates ─────────────────────────────────────────────────────────────

certs: ## Generate test PKI
	@echo "Generating test PKI..."
	@certs/generate.sh

# ── Release (see RELEASE.md) ─────────────────────────────────────────────────
#
# The Release workflow (tag push) runs check-release, builds and tests the
# images natively per architecture, then publish-arch, publish-manifest and
# digests. `publish` is a manual fallback that builds under emulation.

ADAPTERS = open62541 milo
ARCHS    = amd64 arm64

define require_release_version
	@if ! echo "$(VERSION)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "Error: VERSION must be in the form v<major>.<minor>.<patch> (got '$(VERSION)')"; exit 1; fi
endef

check-release: ## Check that VERSION=vX.Y.Z matches the adapter versions and has notes in RELEASE.md
	$(require_release_version)
	@scripts/check-release.sh $(VERSION)

release-notes: ## Print the RELEASE.md section of VERSION=vX.Y.Z (the GitHub release notes)
	$(require_release_version)
	@scripts/release-notes.sh $(VERSION)

publish-arch: ## Push the local images of VERSION as <image>:$(VERSION)-$(ARCH) (build and test them first)
	$(require_release_version)
	@for a in $(ADAPTERS); do \
		img=$(REGISTRY)/opcua-interop-$$a; \
		got=$$(docker image inspect --format '{{.Architecture}}' $$img:$(VERSION)) || exit 1; \
		if [ "$$got" != "$(ARCH)" ]; then echo "Error: $$a:$(VERSION) is $$got, not $(ARCH)"; exit 1; fi; \
		echo "Pushing $$a $(VERSION) for linux/$(ARCH)..."; \
		docker tag $$img:$(VERSION) $$img:$(VERSION)-$(ARCH) || exit 1; \
		docker push --quiet $$img:$(VERSION)-$(ARCH) || exit 1; \
	done

publish-manifest: ## Join the per-architecture images of VERSION into <image>:vX.Y.Z, :vX.Y and :vX
	$(require_release_version)
	@minor=$$(echo $(VERSION) | cut -d. -f1-2); major=$$(echo $(VERSION) | cut -d. -f1); \
	for a in $(ADAPTERS); do \
		img=$(REGISTRY)/opcua-interop-$$a; \
		echo "Creating $$img:$(VERSION) ($$minor, $$major) from: $(ARCHS)"; \
		docker buildx imagetools create --tag $$img:$(VERSION) --tag $$img:$$minor --tag $$img:$$major \
			$(foreach arch,$(ARCHS),$$img:$(VERSION)-$(arch)) || exit 1; \
		for arch in $(ARCHS); do \
			docker buildx imagetools inspect $$img:$(VERSION) --format '{{json .Manifest}}' \
				| tr -d ' \n' | grep -q "\"architecture\":\"$$arch\"" || { echo "Error: $$img:$(VERSION) has no linux/$$arch image"; exit 1; }; \
		done; \
	done

digests: ## Print "<adapter> <digest>" of the multi-arch images of VERSION
	$(require_release_version)
	@for a in $(ADAPTERS); do \
		d=$$(docker buildx imagetools inspect $(REGISTRY)/opcua-interop-$$a:$(VERSION) --format '{{json .Manifest}}' \
			| python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])') || exit 1; \
		echo "$$a $$d"; \
	done

publish: ## Manual fallback: build and push multi-arch images under emulation as VERSION, :vX.Y and :vX
	$(require_release_version)
	@scripts/check-release.sh $(VERSION)
	@minor=$$(echo $(VERSION) | cut -d. -f1-2); major=$$(echo $(VERSION) | cut -d. -f1); \
	for a in $(ADAPTERS); do \
		img=$(REGISTRY)/opcua-interop-$$a; \
		docker buildx build --platform $(PLATFORMS) --push \
			--tag $$img:$(VERSION) --tag $$img:$$minor --tag $$img:$$major \
			--label org.opencontainers.image.version=$(VERSION) \
			--file $$a/Dockerfile $$a/ || exit 1; \
	done
	@echo "Published $(VERSION); create the GitHub release with: make release-notes VERSION=$(VERSION)"

# ── Clean ────────────────────────────────────────────────────────────────────

clean: ## Remove containers and local build artifacts
	@echo "Removing containers and build artifacts..."
	docker compose down --remove-orphans 2>/dev/null || true
	docker rmi $(IMAGE_OPEN62541):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_MILO):$(VERSION) 2>/dev/null || true
	rm -rf open62541/build/ milo/target/

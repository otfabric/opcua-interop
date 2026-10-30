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
IMAGE_ASYNC_OPCUA = $(REGISTRY)/opcua-interop-async-opcua
IMAGE_DOTNET    = $(REGISTRY)/opcua-interop-dotnet
IMAGE_NODE_OPCUA = $(REGISTRY)/opcua-interop-node-opcua

OPEN62541_PORT ?= 4840
MILO_PORT      ?= 4841
ASYNC_OPCUA_PORT ?= 4842
DOTNET_PORT    ?= 4843
NODE_OPCUA_PORT ?= 4844
MQTT_PORT      ?= 1883

# MQTT broker for the PubSub tests (multi-arch index digest of eclipse-mosquitto:2.0.22)
MOSQUITTO_IMAGE ?= eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c

FIXTURE_SCHEMA = fixtures/schema/opcua-fixture.schema.json
FIXTURE_DIRS   = $(wildcard fixtures/*/fixture.json)

.PHONY: help all ci \
        image image-open62541 image-milo image-async-opcua image-dotnet image-node-opcua \
        buildx buildx-open62541 buildx-milo buildx-async-opcua buildx-dotnet buildx-node-opcua \
        validate validate-fixtures \
        test test-open62541 test-milo test-async-opcua test-dotnet test-node-opcua \
        smoke smoke-open62541 smoke-milo smoke-async-opcua smoke-dotnet smoke-node-opcua smoke-cross-stack smoke-cross-dotnet smoke-pubsub smoke-pubsub-dotnet \
        shutdown shutdown-open62541 shutdown-milo shutdown-async-opcua shutdown-dotnet shutdown-node-opcua \
        run-open62541 run-milo run-async-opcua run-dotnet run-node-opcua run-mosquitto \
        candidate certs check-release release-notes publish publish-arch publish-manifest digests clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-26s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: validate image ## Validate fixtures and build local images

# ── Full local CI (mirrors GitHub Actions) ────────────────────────────────────

ci: validate image test smoke shutdown ## Full local CI: validate → build → unit-test → smoke (incl. cross-stack, PubSub) → shutdown
	@echo ""
	@echo "✓ All local CI checks passed."

# ── Local single-arch images (loaded into Docker, used for smoke/dev) ─────────

image: image-open62541 image-milo image-async-opcua image-dotnet image-node-opcua ## Build all adapter images for host architecture

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

image-async-opcua: ## Build async-opcua (Rust) image (host arch, loaded into Docker)
	@echo "Building async-opcua image (host arch)..."
	docker build \
		--tag $(IMAGE_ASYNC_OPCUA):$(VERSION) \
		--file async-opcua/Dockerfile \
		async-opcua/

image-dotnet: ## Build UA-.NETStandard image (host arch, loaded into Docker)
	@echo "Building UA-.NETStandard (dotnet) image (host arch)..."
	docker build \
		--tag $(IMAGE_DOTNET):$(VERSION) \
		--file dotnet/Dockerfile \
		dotnet/

image-node-opcua: ## Build node-opcua (TypeScript) image (host arch, loaded into Docker)
	@echo "Building node-opcua image (host arch)..."
	docker build \
		--tag $(IMAGE_NODE_OPCUA):$(VERSION) \
		--file node-opcua/Dockerfile \
		node-opcua/

# ── Multi-arch buildx (pushes to registry; requires --push or --output) ───────

buildx: buildx-open62541 buildx-milo buildx-async-opcua buildx-dotnet buildx-node-opcua ## Build and push all adapter images (multi-arch)

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

buildx-async-opcua: ## Build and push async-opcua image (multi-arch)
	@echo "Building async-opcua image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_ASYNC_OPCUA):$(VERSION) \
		--file async-opcua/Dockerfile \
		async-opcua/

buildx-dotnet: ## Build and push UA-.NETStandard image (multi-arch)
	@echo "Building UA-.NETStandard (dotnet) image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_DOTNET):$(VERSION) \
		--file dotnet/Dockerfile \
		dotnet/

buildx-node-opcua: ## Build and push node-opcua image (multi-arch)
	@echo "Building node-opcua image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_NODE_OPCUA):$(VERSION) \
		--file node-opcua/Dockerfile \
		node-opcua/

# ── Validation ───────────────────────────────────────────────────────────────

validate: validate-fixtures ## Run all validation checks
	@python3 scripts/check-versions.py
	@scripts/release-notes.sh > /dev/null && echo "ok   RELEASE.md has closed notes for its newest version"

validate-fixtures: ## Validate all fixture files against schema
	@echo "Validating fixture files..."
	@scripts/validate-fixtures.sh

# ── Unit tests (requires images to be built) ──────────────────────────────────

test: test-open62541 test-milo test-async-opcua test-dotnet test-node-opcua ## Run unit tests for all adapters

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

test-async-opcua: image-async-opcua ## Build async-opcua image and run unit tests
	@echo "Running async-opcua unit tests..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_ASYNC_OPCUA):$(VERSION) \
		test

test-dotnet: image-dotnet ## Build UA-.NETStandard image and run unit tests
	@echo "Running UA-.NETStandard (dotnet) unit tests..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_DOTNET):$(VERSION) \
		test

test-node-opcua: image-node-opcua ## Build node-opcua image (runs its unit tests) and run the fixture self-test
	@echo "Running node-opcua unit tests..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_NODE_OPCUA):$(VERSION) \
		test

# ── Smoke tests ──────────────────────────────────────────────────────────────

smoke: smoke-open62541 smoke-milo smoke-async-opcua smoke-dotnet smoke-node-opcua smoke-cross-stack smoke-cross-dotnet smoke-pubsub smoke-pubsub-dotnet ## Run all smoke tests (images must be built)

smoke-open62541: ## Smoke test open62541 adapter (run 'make image-open62541' first)
	@echo "Smoking open62541 adapter..."
	@scripts/smoke.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

smoke-milo: ## Smoke test Milo adapter (run 'make image-milo' first)
	@echo "Smoking Milo adapter..."
	@scripts/smoke.sh milo $(IMAGE_MILO):$(VERSION)

smoke-async-opcua: ## Smoke test async-opcua adapter (run 'make image-async-opcua' first)
	@echo "Smoking async-opcua adapter..."
	@scripts/smoke.sh async-opcua $(IMAGE_ASYNC_OPCUA):$(VERSION)

smoke-dotnet: ## Smoke test UA-.NETStandard adapter (run 'make image-dotnet' first)
	@echo "Smoking UA-.NETStandard (dotnet) adapter..."
	@scripts/smoke.sh dotnet $(IMAGE_DOTNET):$(VERSION)

smoke-node-opcua: ## Smoke test node-opcua adapter (run 'make image-node-opcua' first)
	@echo "Smoking node-opcua adapter..."
	@scripts/smoke.sh node-opcua $(IMAGE_NODE_OPCUA):$(VERSION)

smoke-cross-stack: ## Cross-stack interop self-check (run 'make image' first)
	@echo "Smoking cross-stack interop self-check..."
	@scripts/smoke.sh cross $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION) $(IMAGE_ASYNC_OPCUA):$(VERSION) $(IMAGE_NODE_OPCUA):$(VERSION)

smoke-cross-dotnet: ## Cross-stack smoke: dotnet client/server against open62541 and Milo, node-opcua client against the dotnet history events (run 'make image' first)
	@echo "Smoking cross-stack interop of the dotnet adapter..."
	@scripts/smoke.sh cross-dotnet $(IMAGE_DOTNET):$(VERSION) $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION) $(IMAGE_NODE_OPCUA):$(VERSION)

smoke-pubsub: ## PubSub smoke: UDP / MQTT / security / SKS / codec / information model (open62541)
	@echo "Smoking PubSub (open62541)..."
	@scripts/pubsub-smoke.sh $(IMAGE_OPEN62541):$(VERSION)

smoke-pubsub-dotnet: ## PubSub smoke: UDP / MQTT / security / codec / discovery (UA-.NETStandard)
	@echo "Smoking PubSub (dotnet)..."
	@scripts/pubsub-smoke.sh $(IMAGE_DOTNET):$(VERSION) codec udp-unicast udp-multicast mqtt-uadp mqtt-json udp-secure discovery

# ── Graceful shutdown tests ───────────────────────────────────────────────────

shutdown: shutdown-open62541 shutdown-milo shutdown-async-opcua shutdown-dotnet shutdown-node-opcua ## Test graceful shutdown for all adapters

shutdown-open62541: ## Test open62541 graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing open62541 graceful shutdown..."
	@scripts/shutdown-test.sh open62541 $(IMAGE_OPEN62541):$(VERSION)

shutdown-milo: ## Test Milo graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing Milo graceful shutdown..."
	@scripts/shutdown-test.sh milo $(IMAGE_MILO):$(VERSION)

shutdown-async-opcua: ## Test async-opcua graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing async-opcua graceful shutdown..."
	@scripts/shutdown-test.sh async-opcua $(IMAGE_ASYNC_OPCUA):$(VERSION)

shutdown-dotnet: ## Test UA-.NETStandard graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing UA-.NETStandard (dotnet) graceful shutdown..."
	@scripts/shutdown-test.sh dotnet $(IMAGE_DOTNET):$(VERSION)

shutdown-node-opcua: ## Test node-opcua graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing node-opcua graceful shutdown..."
	@scripts/shutdown-test.sh node-opcua $(IMAGE_NODE_OPCUA):$(VERSION)

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

run-async-opcua: ## Start async-opcua server on port $(ASYNC_OPCUA_PORT)
	@echo "Starting async-opcua server on port $(ASYNC_OPCUA_PORT)..."
	docker run --rm \
		-p $(ASYNC_OPCUA_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		-v "$(PWD)/certs/test-pki:/pki:ro" \
		$(IMAGE_ASYNC_OPCUA):$(VERSION) \
		server \
		--fixture /fixtures/baseline/fixture.json \
		--advertised-host localhost \
		--pki-dir /pki \
		--ready-file /run/opcua-interop/ready

run-dotnet: ## Start UA-.NETStandard server on port $(DOTNET_PORT)
	@echo "Starting UA-.NETStandard (dotnet) server on port $(DOTNET_PORT)..."
	docker run --rm \
		-p $(DOTNET_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_DOTNET):$(VERSION) \
		server \
		--fixture /fixtures/baseline/fixture.json \
		--advertised-host localhost \
		--ready-file /run/opcua-interop/ready

run-node-opcua: ## Start node-opcua server on port $(NODE_OPCUA_PORT)
	@echo "Starting node-opcua server on port $(NODE_OPCUA_PORT)..."
	docker run --rm \
		-p $(NODE_OPCUA_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		-v "$(PWD)/certs/test-pki:/pki:ro" \
		$(IMAGE_NODE_OPCUA):$(VERSION) \
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

# ── opcua-asyncio (asyncua, Python) adapter ──────────────────────────────────
#
# Its own block: the aggregate targets (image, buildx, test, smoke, shutdown,
# clean) get the asyncua targets as extra prerequisites below.

IMAGE_ASYNCUA = $(REGISTRY)/opcua-interop-asyncua
ASYNCUA_PORT ?= 4845

.PHONY: image-asyncua buildx-asyncua test-asyncua smoke-asyncua smoke-cross-asyncua \
        shutdown-asyncua run-asyncua clean-asyncua

image: image-asyncua
buildx: buildx-asyncua
test: test-asyncua
smoke: smoke-asyncua smoke-cross-asyncua
shutdown: shutdown-asyncua
clean: clean-asyncua

image-asyncua: ## Build opcua-asyncio (asyncua) image (host arch, loaded into Docker; runs its unit tests)
	@echo "Building asyncua image (host arch)..."
	docker build \
		--tag $(IMAGE_ASYNCUA):$(VERSION) \
		--file asyncua/Dockerfile \
		asyncua/

buildx-asyncua: ## Build and push asyncua image (multi-arch)
	@echo "Building asyncua image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_ASYNCUA):$(VERSION) \
		--file asyncua/Dockerfile \
		asyncua/

test-asyncua: image-asyncua ## Build asyncua image and run its `test` command on the fixtures
	@echo "Running asyncua unit tests..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_ASYNCUA):$(VERSION) \
		test

smoke-asyncua: ## Smoke test asyncua adapter (run 'make image-asyncua' first)
	@echo "Smoking asyncua adapter..."
	@scripts/smoke.sh asyncua $(IMAGE_ASYNCUA):$(VERSION)

smoke-cross-asyncua: ## Cross-stack smoke: asyncua client/server against open62541 and Milo (run 'make image' first)
	@echo "Smoking cross-stack interop of the asyncua adapter..."
	@scripts/smoke.sh cross-asyncua $(IMAGE_ASYNCUA):$(VERSION) $(IMAGE_OPEN62541):$(VERSION) $(IMAGE_MILO):$(VERSION)

shutdown-asyncua: ## Test asyncua graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing asyncua graceful shutdown..."
	@scripts/shutdown-test.sh asyncua $(IMAGE_ASYNCUA):$(VERSION)

run-asyncua: ## Start asyncua server on port $(ASYNCUA_PORT)
	@echo "Starting asyncua server on port $(ASYNCUA_PORT)..."
	docker run --rm \
		-p $(ASYNCUA_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		-v "$(PWD)/certs/test-pki:/pki:ro" \
		$(IMAGE_ASYNCUA):$(VERSION) \
		server \
		--fixture /fixtures/baseline/fixture.json \
		--advertised-host localhost \
		--pki-dir /pki \
		--ready-file /run/opcua-interop/ready

clean-asyncua:
	docker rmi $(IMAGE_ASYNCUA):$(VERSION) 2>/dev/null || true

# ── UA-.NETStandard GDS (dotnet-gds) adapter ─────────────────────────────────
#
# The GDS pull model (Part 12 §6, §7.9; docs/CLIENT_CONTRACT.md §16) on
# UA-.NETStandard 2.0.1: a Global Discovery Server and `client gds-pull`.
# Its own block like asyncua's: the aggregate targets get it as a prerequisite.

IMAGE_DOTNET_GDS = $(REGISTRY)/opcua-interop-dotnet-gds
DOTNET_GDS_PORT ?= 4846

.PHONY: image-dotnet-gds buildx-dotnet-gds test-dotnet-gds smoke-dotnet-gds \
        shutdown-dotnet-gds run-dotnet-gds clean-dotnet-gds

image: image-dotnet-gds
buildx: buildx-dotnet-gds
test: test-dotnet-gds
smoke: smoke-dotnet-gds
shutdown: shutdown-dotnet-gds
clean: clean-dotnet-gds

image-dotnet-gds: ## Build UA-.NETStandard GDS (dotnet-gds) image (host arch, loaded into Docker)
	@echo "Building UA-.NETStandard GDS (dotnet-gds) image (host arch)..."
	docker build \
		--tag $(IMAGE_DOTNET_GDS):$(VERSION) \
		--file dotnet-gds/Dockerfile \
		dotnet-gds/

buildx-dotnet-gds: ## Build and push dotnet-gds image (multi-arch)
	@echo "Building UA-.NETStandard GDS (dotnet-gds) image (multi-arch, push)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--push \
		--tag $(IMAGE_DOTNET_GDS):$(VERSION) \
		--file dotnet-gds/Dockerfile \
		dotnet-gds/

test-dotnet-gds: image-dotnet-gds ## Build dotnet-gds image and run its `test` command
	@echo "Running dotnet-gds self-test..."
	docker run --rm \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		$(IMAGE_DOTNET_GDS):$(VERSION) \
		test

smoke-dotnet-gds: ## Smoke test dotnet-gds: GDS server + client gds-pull (run 'make image-dotnet-gds' first)
	@echo "Smoking UA-.NETStandard GDS (dotnet-gds) adapter..."
	@scripts/smoke.sh dotnet-gds $(IMAGE_DOTNET_GDS):$(VERSION)

shutdown-dotnet-gds: ## Test dotnet-gds graceful shutdown: SIGTERM must produce exit 0
	@echo "Testing dotnet-gds graceful shutdown..."
	@scripts/shutdown-test.sh dotnet-gds $(IMAGE_DOTNET_GDS):$(VERSION)

run-dotnet-gds: ## Start the dotnet-gds Global Discovery Server on port $(DOTNET_GDS_PORT)
	@echo "Starting dotnet-gds Global Discovery Server on port $(DOTNET_GDS_PORT)..."
	docker run --rm \
		-p $(DOTNET_GDS_PORT):4840 \
		-v "$(PWD)/fixtures:/fixtures:ro" \
		-v "$(PWD)/certs/test-pki:/pki:ro" \
		$(IMAGE_DOTNET_GDS):$(VERSION) \
		server \
		--fixture /fixtures/gds/fixture.json \
		--advertised-host localhost \
		--certificate /pki/dotnet-server/cert.crt \
		--private-key /pki/dotnet-server/cert.key \
		--pki-dir /pki/dotnet-server/pki \
		--ready-file /run/opcua-interop/ready

clean-dotnet-gds:
	docker rmi $(IMAGE_DOTNET_GDS):$(VERSION) 2>/dev/null || true
	rm -rf dotnet-gds/src/bin/ dotnet-gds/src/obj/

# ── Upstream candidates ──────────────────────────────────────────────────────
#
# The daily Upstream workflow (.github/workflows/upstream.yml) compares every
# stack pin with the latest release (scripts/latest-upstream.py) and runs this
# for each pin that is behind. Pins are not changed (see scripts/candidate.sh).

candidate: ## Build and test one adapter at an upstream release: ADAPTER=<adapter> CANDIDATE_VERSION=<version>
	@scripts/candidate.sh $(ADAPTER) $(CANDIDATE_VERSION)

# ── Certificates ─────────────────────────────────────────────────────────────

certs: ## Generate test PKI
	@echo "Generating test PKI..."
	@certs/generate.sh

# ── Release (see RELEASE.md) ─────────────────────────────────────────────────
#
# The Release workflow (run by hand with a patch/minor/major bump) runs check-release, builds and tests the
# images natively per architecture, then publish-arch, publish-manifest and
# digests. `publish` is a manual fallback that builds under emulation.

ADAPTERS = open62541 milo async-opcua dotnet node-opcua asyncua dotnet-gds
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
	docker rmi $(IMAGE_ASYNC_OPCUA):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_DOTNET):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_NODE_OPCUA):$(VERSION) 2>/dev/null || true
	rm -rf open62541/build/ milo/target/ async-opcua/target/ dotnet/src/bin/ dotnet/src/obj/ node-opcua/dist/ node-opcua/node_modules/

# Self-documented Makefile (https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html)
# Run 'make' or 'make help' to list targets.
#
# Pre-push gate:  make ci
# Quick check:    make images smoke

.DEFAULT_GOAL := help

REGISTRY  ?= ghcr.io/otfabric
VERSION   ?= dev
PLATFORMS ?= linux/amd64,linux/arm64

# Registry of the base images on Docker Hub. They are pinned by digest in the
# Dockerfiles, so any mirror of Docker Hub's official images gives the same
# build. The workflows set
#   BASE_REGISTRY=mirror.gcr.io/library
# because anonymous pulls from Docker Hub are rate limited per runner address.
# The dotnet images come from mcr.microsoft.com.
BASE_REGISTRY ?= docker.io/library

# Registry of the images the build tooling itself runs: BuildKit, the QEMU
# handlers, shellcheck, Python. The workflows set TOOLS_REGISTRY=mirror.gcr.io.
TOOLS_REGISTRY ?= docker.io

# Everything that pulls from or pushes to a registry goes through this: it
# repeats a command that failed on a rate limit, a 5xx or a timeout, and only
# then. See scripts/retry.sh.
RETRY := scripts/retry.sh

# Name of the docker-container builder "make buildx-setup" creates.
BUILDER ?= opcua-interop

# Adapters with a published image. The self-tests run over all of them; override
# to work on one: make smoke ADAPTERS=milo
ADAPTERS ?= open62541 milo async-opcua dotnet node-opcua asyncua dotnet-gds
# dotnet-gds is another kind of server: it has its own fixture and only gds-pull.
INTEROP_ADAPTERS = $(filter-out dotnet-gds,$(ADAPTERS))

# MQTT broker for the PubSub tests (multi-arch index digest of eclipse-mosquitto:2.0.22)
MOSQUITTO_IMAGE ?= eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c
MQTT_PORT ?= 1883
PORT      ?= 4840

# BUILDKIT_CACHE=gha shares the layers of an adapter and architecture through
# the GitHub Actions cache, as the workflows do. It needs a docker-container builder.
BUILDKIT_CACHE ?=
comma := ,
cache_flags = $(if $(filter gha,$(BUILDKIT_CACHE)),--load --cache-from type=gha$(comma)scope=$(1)-$(ARCH) --cache-to type=gha$(comma)mode=max$(comma)scope=$(1)-$(ARCH))
build_cmd   = $(if $(filter gha,$(BUILDKIT_CACHE)),docker buildx build,docker build)

image = $(REGISTRY)/opcua-interop-$(1)
labels = --label org.opencontainers.image.source=https://github.com/otfabric/opcua-interop \
	--label org.opencontainers.image.revision=$(shell git rev-parse HEAD 2>/dev/null) \
	--label org.opencontainers.image.version=$(VERSION)

export REGISTRY VERSION

# image-%, smoke-%, candidate-% and run-% are pattern rules, which make ignores
# for .PHONY targets: they depend on FORCE instead.
.PHONY: help all ci validate documents lint images smoke interop pubsub capabilities certs check-release \
        release-notes run-mosquitto buildx-setup buildx publish publish-arch publish-manifest digests clean FORCE
FORCE:

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_%-]+:.*?## / {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: validate images ## Validate fixtures and build the local images

ci: validate lint images documents ## Full local CI: validate, lint, build, smoke, cross-stack and PubSub self-tests, document schemas
	@echo ""
	@echo "All local CI checks passed."

# ── Validation ───────────────────────────────────────────────────────────────

validate: ## Validate every fixture against the schema and the cross-field rules; check versions.yaml and RELEASE.md
	@scripts/check-versions.sh
	@scripts/release-notes.sh > /dev/null && echo "ok   RELEASE.md has the notes of its newest version"
	@python3 -m unittest discover -q -s scripts -p 'test_*.py'
	@echo "Validating fixtures..."
	@if python3 -c 'import jsonschema' 2>/dev/null; then \
		python3 scripts/validate-fixtures.py --require-schema; \
	else \
		echo "(jsonschema not installed locally: running the validator in a container)"; \
		$(RETRY) docker run --rm -v "$(CURDIR):/work:ro" -w /work $(TOOLS_REGISTRY)/library/python:3.12-slim \
			sh -c 'pip install -q --root-user-action=ignore jsonschema && python scripts/validate-fixtures.py --require-schema'; \
	fi

documents: ## Run the self-tests keeping every document, and validate them against schemas/
	@rm -rf reports && mkdir -p reports
	@REPORT_DIR=reports $(MAKE) --no-print-directory smoke interop pubsub
	@echo "Validating documents..."
	@if python3 -c 'import jsonschema' 2>/dev/null; then \
		python3 scripts/validate-documents.py reports; \
	else \
		$(RETRY) docker run --rm -v "$(CURDIR):/work:ro" -w /work $(TOOLS_REGISTRY)/library/python:3.12-slim \
			sh -c 'pip install -q --root-user-action=ignore jsonschema && python scripts/validate-documents.py reports'; \
	fi

lint: ## Shellcheck the scripts (the installed shellcheck, or a container when there is none)
	@echo "Linting scripts..."
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck --severity=warning -x -P scripts scripts/*.sh certs/generate.sh; \
	else \
		$(RETRY) docker run --rm -v "$(CURDIR):/mnt:ro" $(TOOLS_REGISTRY)/koalaman/shellcheck:stable --severity=warning -x -P scripts scripts/*.sh certs/generate.sh; \
	fi

# ── Local single-arch images (loaded into Docker; used by smoke and interop) ──

images: $(addprefix image-,$(ADAPTERS)) ## Build every adapter image for the host architecture

image-%: FORCE ## Build one adapter image, e.g. image-milo
	@echo "Building $* image ($(VERSION))..."
	@$(RETRY) $(build_cmd) $(call cache_flags,$*) \
		--build-arg BASE_REGISTRY=$(BASE_REGISTRY) $(labels) \
		--tag $(call image,$*):$(VERSION) \
		--file adapters/$*/Dockerfile \
		.

# ── Self-tests (images must be built) ─────────────────────────────────────────

smoke: $(addprefix smoke-,$(ADAPTERS)) ## Container-contract smoke test of every adapter

smoke-%: FORCE ## Smoke test one adapter, e.g. smoke-milo
	@scripts/smoke.sh $*

interop: ## Cross-stack self-test: every client against every server
	@scripts/interop.sh $(INTEROP_ADAPTERS)

pubsub: ## PubSub self-test: the open62541 set and the UA-.NETStandard set
	@MOSQUITTO_IMAGE=$(BASE_REGISTRY)/$(MOSQUITTO_IMAGE) scripts/pubsub-smoke.sh open62541
	@MOSQUITTO_IMAGE=$(BASE_REGISTRY)/$(MOSQUITTO_IMAGE) scripts/pubsub-smoke.sh dotnet codec udp-unicast udp-multicast mqtt-uadp mqtt-json udp-secure discovery

capabilities: ## Print the capability document of every local image
	@for a in $(ADAPTERS); do docker run --rm $(call image,$$a):$(VERSION) print-capabilities | jq -c '{adapter, stack, roles}'; done

certs: ## Generate the test PKI (certs/test-pki)
	@certs/generate.sh

# ── Upstream candidates ───────────────────────────────────────────────────────
# Builds an adapter at another upstream release than the pin and self-tests it
# against the pinned open62541 and Milo. Pins are not changed (see
# scripts/candidate.sh). Deviations of that version listed in tests/known-bugs.tsv
# are reported as known, so the run shows whether everything else still works.
# The Upstream workflow runs this for every pin that is behind.

candidate-%: FORCE ## Build and self-test one adapter at an upstream release, e.g. candidate-milo CANDIDATE=1.1.9
	@test -n "$(CANDIDATE)" || { echo "Error: CANDIDATE=<upstream version> is required"; exit 1; }
	@scripts/candidate.sh $* $(CANDIDATE)

# ── Running a server by hand ──────────────────────────────────────────────────

run-%: FORCE ## Run one adapter's server on 127.0.0.1:$(PORT), e.g. run-milo
	docker run --rm -p 127.0.0.1:$(PORT):4840 -v "$(CURDIR)/fixtures:/fixtures:ro" $(call image,$*):$(VERSION) \
		server --fixture /fixtures/$(if $(filter dotnet-gds,$*),gds,baseline)/fixture.json --advertised-host localhost \
		--ready-file /run/opcua-interop/ready

run-mosquitto: ## Run the MQTT broker for the PubSub tests on 127.0.0.1:$(MQTT_PORT)
	docker run --rm -p 127.0.0.1:$(MQTT_PORT):1883 -v "$(CURDIR)/fixtures/pubsub/mosquitto.conf:/mosquitto-interop.conf:ro" \
		$(BASE_REGISTRY)/$(MOSQUITTO_IMAGE) mosquitto -c /mosquitto-interop.conf

# ── Multi-arch build and publish ──────────────────────────────────────────────

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

buildx-setup: ## Prepare multi-arch builds: QEMU handlers and a docker-container builder (pulled through TOOLS_REGISTRY)
	@echo "Installing QEMU handlers and creating builder $(BUILDER)..."
	@$(RETRY) docker run --privileged --rm $(TOOLS_REGISTRY)/tonistiigi/binfmt:latest --install arm64,amd64 >/dev/null
	@docker buildx rm $(BUILDER) >/dev/null 2>&1 || true
	@$(RETRY) docker buildx create --name $(BUILDER) --driver docker-container \
		--driver-opt image=$(TOOLS_REGISTRY)/moby/buildkit:buildx-stable-1 --bootstrap >/dev/null
	@docker buildx inspect $(BUILDER) | grep -E '^(Name|Driver|Platforms)' || true

# Uses the builder of buildx-setup when there is one, the current builder otherwise.
builder_flag = $(shell docker buildx inspect $(BUILDER) >/dev/null 2>&1 && echo --builder $(BUILDER))

buildx: ## Build every image for $(PLATFORMS) under emulation, without pushing (local check; CI builds natively on both)
	@for a in $(ADAPTERS); do \
		echo "Building $$a for $(PLATFORMS)..."; \
		$(RETRY) docker buildx build $(builder_flag) --platform $(PLATFORMS) \
			--build-arg BASE_REGISTRY=$(BASE_REGISTRY) \
			--file adapters/$$a/Dockerfile . || exit 1; \
	done

publish: ## Manual fallback: build and push multi-arch images under emulation as VERSION, :vX.Y and :vX
	$(require_release_version)
	@scripts/check-release.sh $(VERSION)
	@minor=$$(echo $(VERSION) | cut -d. -f1-2); major=$$(echo $(VERSION) | cut -d. -f1); \
	for a in $(ADAPTERS); do \
		echo "Publishing $$a $(VERSION) for $(PLATFORMS)..."; \
		img=$(call image,$$a); \
		$(RETRY) docker buildx build $(builder_flag) --platform $(PLATFORMS) --push \
			--build-arg BASE_REGISTRY=$(BASE_REGISTRY) $(labels) \
			--tag $$img:$(VERSION) --tag $$img:$$minor --tag $$img:$$major \
			--file adapters/$$a/Dockerfile . || exit 1; \
	done
	@echo "Published $(VERSION); create the GitHub release with: make release-notes VERSION=$(VERSION)"

# ── Multi-arch publish from native runners ────────────────────────────────────
# The release workflow builds on an amd64 and on an arm64 runner (no emulation),
# self-tests there and pushes what it tested under <image>:<version>-<arch>. A
# last job joins the two into <image>:<version>, :<major>.<minor> and :<major>.

ARCH ?= $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
ARCHS ?= amd64 arm64

publish-arch: ## Push the local images of this machine as <image>:$(VERSION)-$(ARCH) (build and self-test them first)
	$(require_release_version)
	@for a in $(ADAPTERS); do \
		img=$(call image,$$a); \
		got=$$(docker image inspect --format '{{.Architecture}}' $$img:$(VERSION)) || exit 1; \
		if [ "$$got" != "$(ARCH)" ]; then echo "Error: $$a:$(VERSION) is $$got, not $(ARCH)"; exit 1; fi; \
		echo "Pushing $$a $(VERSION) for linux/$(ARCH)..."; \
		docker tag $$img:$(VERSION) $$img:$(VERSION)-$(ARCH) || exit 1; \
		$(RETRY) docker push --quiet $$img:$(VERSION)-$(ARCH) || exit 1; \
	done

publish-manifest: ## Join the per-architecture images of VERSION into <image>:vX.Y.Z, :vX.Y and :vX
	$(require_release_version)
	@minor=$$(echo $(VERSION) | cut -d. -f1-2); major=$$(echo $(VERSION) | cut -d. -f1); \
	for a in $(ADAPTERS); do \
		img=$(call image,$$a); \
		echo "Creating $$img:$(VERSION) ($$minor, $$major) from: $(ARCHS)"; \
		$(RETRY) docker buildx imagetools create --tag $$img:$(VERSION) --tag $$img:$$minor --tag $$img:$$major \
			$(foreach arch,$(ARCHS),$$img:$(VERSION)-$(arch)) || exit 1; \
		for arch in $(ARCHS); do \
			$(RETRY) docker buildx imagetools inspect $$img:$(VERSION) --format '{{json .Manifest}}' \
				| tr -d ' \n' | grep -q "\"architecture\":\"$$arch\"" || { echo "Error: $$img:$(VERSION) has no linux/$$arch image"; exit 1; }; \
		done; \
	done

digests: ## Print "<adapter> <digest>" of the published multi-arch images of VERSION
	$(require_release_version)
	@for a in $(ADAPTERS); do \
		d=$$($(RETRY) docker buildx imagetools inspect $(call image,$$a):$(VERSION) --format '{{.Manifest.Digest}}') || exit 1; \
		echo "$$a $$d"; \
	done

# ── Clean ─────────────────────────────────────────────────────────────────────

clean: ## Remove test containers, networks, local images and reports
	@docker ps -aq --filter "label=opcua-interop.run" | xargs -r docker rm -f >/dev/null 2>&1 || true
	@docker network ls --format '{{.Name}}' | grep '^opcua-interop-' | xargs -r docker network rm >/dev/null 2>&1 || true
	@docker compose down --remove-orphans 2>/dev/null || true
	@for a in $(ADAPTERS); do docker rmi $(call image,$$a):$(VERSION) 2>/dev/null || true; done
	@rm -rf reports adapters/open62541/build adapters/milo/target adapters/async-opcua/target adapters/dotnet/src/bin adapters/dotnet/src/obj adapters/dotnet-gds/src/bin adapters/dotnet-gds/src/obj adapters/node-opcua/dist adapters/node-opcua/node_modules

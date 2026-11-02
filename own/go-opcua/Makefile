# The opcua-interop-otfabric image, from the repository root:
#   make -f own/go-opcua/Makefile image check
#
# Apart from the top-level Makefile on purpose: this image is not in ADAPTERS
# and not in a release of the harness.

IMAGE ?= ghcr.io/otfabric/opcua-interop-otfabric:dev
# The harness release of the reference images to test against.
VERSION ?= $(shell git tag -l 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)
REFERENCES ?= open62541 milo async-opcua dotnet node-opcua asyncua dotnet-gds
BASE_REGISTRY ?= docker.io/library
# The broker of the PubSub scenarios (docs/CAPABILITIES.md "MQTT broker").
MOSQUITTO_IMAGE ?= eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c

# The latest go-opcua release, as the workflow builds it.
UPSTREAM_VERSION ?= $(shell git ls-remote --tags --refs https://github.com/otfabric/go-opcua.git 'v[0-9]*' | sed 's,.*refs/tags/,,' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | sort -V | tail -1)
UPSTREAM_SHA ?= $(shell git ls-remote --tags https://github.com/otfabric/go-opcua.git 'refs/tags/$(UPSTREAM_VERSION)^{}' | cut -f1)

export VERSION
export ADAPTER_IMAGE_otfabric = $(IMAGE)

.PHONY: image check smoke interop pubsub

image:
	docker build --build-arg BASE_REGISTRY=$(BASE_REGISTRY) --build-arg UPSTREAM_VERSION=$(UPSTREAM_VERSION) --build-arg UPSTREAM_SHA=$(UPSTREAM_SHA) --build-arg ADAPTER_VERSION=$(UPSTREAM_VERSION) --tag $(IMAGE) --file own/go-opcua/Dockerfile .

# Every suite runs, whatever an earlier one found.
check:
	@$(MAKE) -k -f own/go-opcua/Makefile smoke interop pubsub

smoke:
	scripts/smoke.sh otfabric

interop:
	scripts/interop.sh otfabric $(REFERENCES)

pubsub:
	MOSQUITTO_IMAGE=$(BASE_REGISTRY)/$(MOSQUITTO_IMAGE) scripts/pubsub-own.sh otfabric

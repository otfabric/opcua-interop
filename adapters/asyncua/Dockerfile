# opcua-interop adapter for opcua-asyncio (PyPI "asyncua"), see README.md.
# Build from the repository root:
#   docker build -f adapters/asyncua/Dockerfile -t opcua-interop-asyncua:local .
#
# The stack is asyncua from PyPI, pinned exactly (asyncua==2.1.0) in
# requirements.in and, with every transitive dependency, by hash in
# requirements.txt. Every dependency is a pure-Python or manylinux / abi3
# wheel (--only-binary=:all:), so the same Dockerfile builds natively for
# linux/amd64 and linux/arm64 without a compiler. The base image is pinned
# by its multi-arch index digest (python:3.14.9-slim-trixie).

# Where the base image comes from: pinned by digest, so a mirror of Docker Hub
# serves the same image (see the Makefile).
ARG BASE_REGISTRY=docker.io/library

# ---------------------------------------------------------------------------
# Stage 1: virtualenv with the locked wheels; the unit tests run here, so an
# image is only produced when they pass. `docker run <image> test` checks the
# mounted fixtures.
# ---------------------------------------------------------------------------
FROM ${BASE_REGISTRY}/python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv

COPY adapters/asyncua/requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --require-hashes --no-deps --only-binary=:all: -r /tmp/requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip \
 && rm -rf /opt/venv/lib/python*/site-packages/asyncua/tests

COPY adapters/asyncua/src/ /opt/app/
COPY adapters/asyncua/tests/ /opt/test/tests/
COPY adapters/asyncua/testdata/ /opt/test/testdata/
RUN cd /opt/test && PYTHONPATH=/opt/app /opt/venv/bin/python -m unittest discover -s tests -v \
 && /opt/venv/bin/python -m compileall -q /opt/app /opt/venv/lib

# ---------------------------------------------------------------------------
# Stage 2: runtime (no tests, no pip, non-root)
# ---------------------------------------------------------------------------
FROM ${BASE_REGISTRY}/python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58 AS runtime

RUN groupadd --system --gid 10001 opcua \
 && useradd --system --uid 10001 --gid opcua --home-dir /nonexistent --shell /usr/sbin/nologin opcua \
 && mkdir -p /run/opcua-interop/pki /fixtures \
 && chown -R opcua:opcua /run/opcua-interop

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/app /opt/app

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/opt/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OPCUA_FIXTURE=/fixtures/fixture.json

USER opcua
WORKDIR /tmp
EXPOSE 4840

HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=30 \
  CMD test -f /run/opcua-interop/ready

ENTRYPOINT ["python", "-m", "opcua_interop_asyncua"]
CMD ["server"]

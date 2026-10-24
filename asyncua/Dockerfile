# opcua-interop adapter for opcua-asyncio (PyPI "asyncua"), see README.md.
# Build from the asyncua/ directory:
#   docker build -f asyncua/Dockerfile -t opcua-interop-asyncua:local asyncua/
#
# The stack is asyncua from PyPI, pinned exactly (asyncua==2.1.0) in
# requirements.in and, with every transitive dependency, by hash in
# requirements.txt. Every dependency is a pure-Python or manylinux / abi3
# wheel (--only-binary=:all:), so the same Dockerfile builds natively for
# linux/amd64 and linux/arm64 without a compiler. The base image is pinned
# by its multi-arch index digest (python:3.14.9-slim-trixie).

# ---------------------------------------------------------------------------
# Stage 1: virtualenv with the locked wheels; the unit tests run here, so an
# image is only produced when they pass. `docker run <image> test` checks the
# mounted fixtures.
# ---------------------------------------------------------------------------
FROM python:3.14.9-slim-trixie@sha256:b347e2dcbc7f0b6f9fb7182e9da6a187fb10ae715e0692518c1aed0eec94a700 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv

COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --require-hashes --no-deps --only-binary=:all: -r /tmp/requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip \
 && rm -rf /opt/venv/lib/python*/site-packages/asyncua/tests

COPY src/ /opt/app/
COPY tests/ /opt/test/tests/
COPY testdata/ /opt/test/testdata/
RUN cd /opt/test && PYTHONPATH=/opt/app /opt/venv/bin/python -m unittest discover -s tests -v \
 && /opt/venv/bin/python -m compileall -q /opt/app /opt/venv/lib

# ---------------------------------------------------------------------------
# Stage 2: runtime (no tests, no pip, non-root)
# ---------------------------------------------------------------------------
FROM python:3.14.9-slim-trixie@sha256:b347e2dcbc7f0b6f9fb7182e9da6a187fb10ae715e0692518c1aed0eec94a700 AS runtime

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

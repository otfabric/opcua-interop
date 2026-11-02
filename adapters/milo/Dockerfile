# Where the base images come from: pinned by digest, so a mirror of Docker Hub
# serves the same images (see the Makefile). Build from the repository root.
ARG BASE_REGISTRY=docker.io/library
ARG MAVEN_VERSION=3.9.16
ARG MAVEN_DIGEST=sha256:93b8a14ea2f412782e4e842651273b4d903e35cc496284f178fbbe2d67d00976
ARG TEMURIN_JRE_DIGEST=sha256:659b528cca74a0edc5c25315ec5819f35bce40bbcec645c4c534987e4c6be7c1
ARG MILO_VERSION=

# Stage 1: build — use the official maven image (Maven + JDK pre-installed)
FROM ${BASE_REGISTRY}/maven:${MAVEN_VERSION}-eclipse-temurin-25@${MAVEN_DIGEST} AS builder

ARG MILO_VERSION

WORKDIR /build

COPY adapters/milo/pom.xml .
RUN mvn -B dependency:go-offline -q ${MILO_VERSION:+-Dmilo.version=${MILO_VERSION}}

COPY adapters/milo/src/ src/
RUN mvn -B package -DskipTests ${MILO_VERSION:+-Dmilo.version=${MILO_VERSION}} && \
    cp target/opcua-interop-milo-*.jar target/opcua-interop-milo.jar

# Stage 2: runtime
FROM ${BASE_REGISTRY}/eclipse-temurin:25-jre-jammy@${TEMURIN_JRE_DIGEST} AS runtime

RUN mkdir -p /app /run/opcua-interop

COPY --from=builder /build/target/opcua-interop-milo.jar /app/opcua-interop-milo.jar

EXPOSE 4840

ENTRYPOINT ["java", "-jar", "/app/opcua-interop-milo.jar"]

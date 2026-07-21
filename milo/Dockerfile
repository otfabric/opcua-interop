ARG MAVEN_VERSION=3.9.16
ARG MILO_VERSION=

# Stage 1: build — use the official maven image (Maven + JDK pre-installed)
FROM maven:${MAVEN_VERSION}-eclipse-temurin-25 AS builder

ARG MILO_VERSION

WORKDIR /build

COPY pom.xml .
RUN mvn -B dependency:go-offline -q ${MILO_VERSION:+-Dmilo.version=${MILO_VERSION}}

COPY src/ src/
RUN mvn -B package -DskipTests ${MILO_VERSION:+-Dmilo.version=${MILO_VERSION}} && \
    cp target/opcua-interop-milo-*.jar target/opcua-interop-milo.jar

# Stage 2: runtime
FROM eclipse-temurin:25-jre-jammy AS runtime

RUN mkdir -p /app /run/opcua-interop

COPY --from=builder /build/target/opcua-interop-milo.jar /app/opcua-interop-milo.jar

EXPOSE 4840

ENTRYPOINT ["java", "-jar", "/app/opcua-interop-milo.jar"]

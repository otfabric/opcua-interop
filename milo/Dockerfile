ARG MAVEN_VERSION=3.9.8

# Stage 1: build
FROM eclipse-temurin:21-jdk-jammy AS builder

ARG MAVEN_VERSION

RUN apt-get update -o Acquire::AllowInsecureRepositories=true \
    -o Acquire::AllowDowngradeToInsecureRepositories=true && \
    apt-get install -y --no-install-recommends --allow-unauthenticated curl ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL \
      "https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
      | tar -xzC /opt && \
    ln -s "/opt/apache-maven-${MAVEN_VERSION}/bin/mvn" /usr/local/bin/mvn

WORKDIR /build

COPY pom.xml .
RUN mvn -B dependency:go-offline -q

COPY src/ src/
RUN mvn -B package -DskipTests && \
    cp target/opcua-interop-milo-*.jar target/opcua-interop-milo.jar

# Stage 2: runtime
FROM eclipse-temurin:21-jre-jammy AS runtime

RUN mkdir -p /app /run/opcua-interop

COPY --from=builder /build/target/opcua-interop-milo.jar /app/opcua-interop-milo.jar

EXPOSE 4840

ENTRYPOINT ["java", "-jar", "/app/opcua-interop-milo.jar"]

# opcua-interop adapter for the GDS of the OPC Foundation UA-.NETStandard stack
# (Part 12 pull model: a Global Discovery Server and a GDS client).
#
# A separate project from dotnet/ (its own capability document, the GDS server
# instead of the fixture address space), on UA-.NETStandard 2.0.1 with every
# Opc.Ua package (including Opc.Ua.Gds.Server / Opc.Ua.Gds.Client) pinned to it.
#
# The build stage runs on the build platform ($BUILDPLATFORM): the publish
# output is portable IL (framework-dependent, no apphost), so a multi-platform
# buildx run (linux/amd64 + linux/arm64) never compiles under emulation.
ARG DOTNET_SDK_VERSION=10.0.402
ARG DOTNET_RUNTIME_VERSION=10.0.13
ARG DOTNET_SDK_DIGEST=sha256:747cbade5bfd918a175ac32f8f1d931edec2c7d0d5397a3de72eaef1ac1f66d2
ARG DOTNET_RUNTIME_DIGEST=sha256:6a97a629f6c44e7263b41175e79cb9aeb1df631d3714e74e80a4ddd016258646
ARG OPCUA_VERSION=2.0.1

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_VERSION}-noble@${DOTNET_SDK_DIGEST} AS build
ARG OPCUA_VERSION
WORKDIR /src
COPY adapters/dotnet-gds/src/OpcUaInterop.DotnetGds.csproj ./
RUN dotnet restore -p:OpcUaVersion=${OPCUA_VERSION}
COPY adapters/dotnet-gds/src/ ./
RUN dotnet publish -c Release --no-restore -p:OpcUaVersion=${OPCUA_VERSION} -p:UseAppHost=false -o /app

FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_RUNTIME_VERSION}-alpine3.24@${DOTNET_RUNTIME_DIGEST} AS runtime
# The .NET images ship the non-root user "app" (UID 1654).
RUN mkdir -p /run/opcua-interop/pki && chown -R app:app /run/opcua-interop
COPY --from=build /app /app
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_gcServer=0
USER app
EXPOSE 4840
ENTRYPOINT ["dotnet", "/app/opcua-interop-dotnet-gds.dll"]

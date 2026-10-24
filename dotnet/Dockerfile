# opcua-interop adapter for the OPC Foundation UA-.NETStandard stack.
#
# The build stage runs on the build platform ($BUILDPLATFORM): the publish
# output is portable IL (framework-dependent, no apphost), so a multi-platform
# buildx run (linux/amd64 + linux/arm64) never compiles under emulation.
ARG DOTNET_SDK_VERSION=10.0.402
ARG DOTNET_RUNTIME_VERSION=10.0.13
ARG OPCUA_VERSION=2.0.1

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_VERSION}-noble AS build
ARG OPCUA_VERSION
WORKDIR /src
COPY src/OpcUaInterop.Dotnet.csproj ./
RUN dotnet restore -p:OpcUaVersion=${OPCUA_VERSION}
COPY src/ ./
RUN dotnet publish -c Release --no-restore -p:OpcUaVersion=${OPCUA_VERSION} -p:UseAppHost=false -o /app

FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_RUNTIME_VERSION}-alpine3.24 AS runtime
# The .NET images ship the non-root user "app" (UID 1654).
RUN mkdir -p /run/opcua-interop/pki && chown -R app:app /run/opcua-interop
COPY --from=build /app /app
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_gcServer=0
USER app
EXPOSE 4840
ENTRYPOINT ["dotnet", "/app/opcua-interop-dotnet.dll"]

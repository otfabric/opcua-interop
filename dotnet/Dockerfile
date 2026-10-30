# opcua-interop adapter for the OPC Foundation UA-.NETStandard stack.
#
# The build stage runs on the build platform ($BUILDPLATFORM): the publish
# output is portable IL (framework-dependent, no apphost), so a multi-platform
# buildx run (linux/amd64 + linux/arm64) never compiles under emulation.
ARG DOTNET_SDK_VERSION=10.0.402
ARG DOTNET_RUNTIME_VERSION=10.0.13
ARG DOTNET_SDK_DIGEST=sha256:747cbade5bfd918a175ac32f8f1d931edec2c7d0d5397a3de72eaef1ac1f66d2
ARG DOTNET_RUNTIME_DIGEST=sha256:ecf8dcbaab8ebc4bdfb2322d6fe4217bbb118894310ebb6d53c580874ab4b27d
ARG OPCUA_VERSION=2.0.1

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_VERSION}-noble@${DOTNET_SDK_DIGEST} AS build
ARG OPCUA_VERSION
WORKDIR /src
COPY src/OpcUaInterop.Dotnet.csproj ./
RUN dotnet restore -p:OpcUaVersion=${OPCUA_VERSION}
COPY src/ ./
RUN dotnet publish -c Release --no-restore -p:OpcUaVersion=${OPCUA_VERSION} -p:UseAppHost=false -o /app

# The ASP.NET Core runtime: the opc.https / opc.wss listeners of
# Opc.Ua.Bindings.Https are hosted by Kestrel.
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_RUNTIME_VERSION}-alpine3.24@${DOTNET_RUNTIME_DIGEST} AS runtime
# The .NET images ship the non-root user "app" (UID 1654).
RUN mkdir -p /run/opcua-interop/pki && chown -R app:app /run/opcua-interop
COPY --from=build /app /app
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_gcServer=0
USER app
EXPOSE 4840 4843 4844
ENTRYPOINT ["dotnet", "/app/opcua-interop-dotnet.dll"]

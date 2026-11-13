# syntax=docker/dockerfile:1
#
# GoldfishSend server image. One image serves both roles; pick one per container with
# Goldfish__Roles=api or Goldfish__Roles=worker (the default "api,worker" runs both in one process).
#
#   docker build -t goldfishsend server/          (or: podman build -t goldfishsend server/)
#   docker run --rm goldfishsend keygen           (prints a fresh key set; see server/README.md)
#
# No secrets are baked in. Keys and connection strings come from the environment (or a mounted
# appsettings.Production.json) at run time.

# ---------------------------------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
WORKDIR /src

# Restore first, from the project files only, so the package layer is cached across source edits.
COPY Directory.Build.props ./
COPY src/GoldfishSend.Core/GoldfishSend.Core.csproj src/GoldfishSend.Core/packages.lock.json src/GoldfishSend.Core/
COPY src/GoldfishSend.Infrastructure/GoldfishSend.Infrastructure.csproj src/GoldfishSend.Infrastructure/packages.lock.json src/GoldfishSend.Infrastructure/
COPY src/GoldfishSend.Api/GoldfishSend.Api.csproj src/GoldfishSend.Api/packages.lock.json src/GoldfishSend.Api/
COPY tools/HealthProbe/HealthProbe.csproj tools/HealthProbe/packages.lock.json tools/HealthProbe/
# --locked-mode: the build fails if a dependency differs from the committed packages.lock.json files.
RUN dotnet restore src/GoldfishSend.Api/GoldfishSend.Api.csproj --locked-mode \
 && dotnet restore tools/HealthProbe/HealthProbe.csproj --locked-mode

COPY src/ src/
COPY tools/ tools/
# Development settings never ship (rm at the end).
RUN dotnet publish src/GoldfishSend.Api/GoldfishSend.Api.csproj \
        -c Release --no-restore -o /out/app -p:UseAppHost=false \
 && dotnet publish tools/HealthProbe/HealthProbe.csproj \
        -c Release --no-restore -o /out/probe -p:UseAppHost=false \
 && rm -f /out/app/appsettings.Development.json

# ---------------------------------------------------------------------------------------------------
# Runtime: Ubuntu Noble "chiseled" ASP.NET image. It is distroless: no shell, no package manager,
# and a non-root user (`app`, UID 1654) by default. ICU is not needed (InvariantGlobalization=true).
# ---------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime

LABEL org.opencontainers.image.title="GoldfishSend" \
      org.opencontainers.image.description="Privacy-maximal blind push relay"

# ASPNETCORE_HTTP_PORTS is cleared so Kestrel binds only ASPNETCORE_URLS (no override warning).
# Server GC: .NET 9+ enables DATAS (dynamic heap sizing) with it by default, so it stays lean in small containers.
# EnableDiagnostics=0: no diagnostics IPC socket, debugger or profiler attach. No crash dumps either,
# because a dump would contain key material.
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_HTTP_PORTS= \
    DOTNET_gcServer=1 \
    DOTNET_EnableDiagnostics=0 \
    DOTNET_DbgEnableMiniDump=0

WORKDIR /app
COPY --from=build /out/app ./
COPY --from=build /out/probe ./probe/

USER $APP_UID
EXPOSE 8080

# HEALTHCHECK is not set here because OCI images (podman's default format) ignore it.
# Compose runs: dotnet /app/probe/HealthProbe.dll http://127.0.0.1:8080/readyz
ENTRYPOINT ["dotnet", "GoldfishSend.Api.dll"]

# Build context: examples/CA/ (set by DockerfileContext in Sigil.csproj)
#
# VS builds this automatically via Docker launch profile.
# Aspire uses the pre-built image via AddContainer("sigil", "sigil", "dev").

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 5200
EXPOSE 7200

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Sigil/Sigil.csproj                                 Sigil/
COPY Sigil.Common/Sigil.Common.csproj                    Sigil.Common/
COPY Sigil.UI/Sigil.UI.csproj                            Sigil.UI/
COPY Sigil.ServiceDefaults/Sigil.ServiceDefaults.csproj  Sigil.ServiceDefaults/
COPY Sigil.Vault.Transit/Sigil.Vault.Transit.csproj      Sigil.Vault.Transit/
COPY Sigil.Gcp.Kms/Sigil.Gcp.Kms.csproj                 Sigil.Gcp.Kms/

RUN dotnet restore Sigil/Sigil.csproj

COPY Sigil/               Sigil/
COPY Sigil.Common/        Sigil.Common/
COPY Sigil.UI/            Sigil.UI/
COPY Sigil.ServiceDefaults/ Sigil.ServiceDefaults/
COPY Sigil.Vault.Transit/ Sigil.Vault.Transit/
COPY Sigil.Gcp.Kms/      Sigil.Gcp.Kms/

ARG BUILD_CONFIGURATION=Release
RUN dotnet publish Sigil/Sigil.csproj -c $BUILD_CONFIGURATION -o /app/publish

# Generate dev cert in the SDK stage (aspnet runtime doesn't have dev-certs tool)
FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "Sigil.dll"]

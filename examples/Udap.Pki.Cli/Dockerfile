# Build from examples/Udap.Pki.Cli:
#   docker build -t udap-pki-cli .
#
# Via Cloud Build:
#   gcloud builds submit --config cloudbuild.yaml --substitutions=TAG_NAME="0.0.1"
#
# Cloud Run Job (default): runs crl-update-all --prod automatically
#   docker run -e CA_P12_PASSWORD=secret udap-pki-cli
#
# Interactive use:
#   docker run -it --name udap-pki-cli -v udap-pki-gcloud:/root/.config/gcloud --entrypoint /bin/bash udap-pki-cli
#   docker start -ai udap-pki-cli
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

COPY ["Directory.Packages.props", "."]
COPY ["Udap.Pki.Cli.csproj", "."]
RUN dotnet restore "Udap.Pki.Cli.csproj"
COPY . .

RUN dotnet build "Udap.Pki.Cli.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "Udap.Pki.Cli.csproj" -c $BUILD_CONFIGURATION -o /app/publish

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS final

# Install gcloud CLI (needed for CDN cache invalidation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gnupg apt-transport-https ca-certificates && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && \
    apt-get install -y --no-install-recommends google-cloud-cli && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=publish /app/publish .

ENTRYPOINT ["./Udap.Pki.Cli"]
CMD ["crl-update-all", "--prod"]

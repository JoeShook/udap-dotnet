# Running the examples

The example servers are meant to run together. [`Udap.AppHost`](./Udap.AppHost/) is a .NET Aspire AppHost that starts them all, plus Postgres and pgAdmin, and gives you a dashboard of what is running where.

## Before the first run

- **.NET 10 SDK** and **Docker** (Docker Desktop or Podman) running.
- **A trusted ASP.NET dev certificate.** Every server serves HTTPS with it, and its SAN includes `*.dev.localhost`:

  ```bash
  dotnet dev-certs https --trust
  ```

- **The test PKI.** The UDAP certificates the servers sign metadata with, and trust, come from `_tests/Udap.PKI.Generator` (see [Certificates](#certificates)).

## Start

```bash
dotnet run --project examples/Udap.AppHost
```

The console prints the dashboard login link. The AppHost creates the databases, runs `migrations/UdapDb.Postgres` once per database to apply the schema and seed data, then starts the servers.

| Server | URL | Starts |
|:---|:---|:---|
| Udap.Auth.Server | https://udap-auth-server.dev.localhost:5002 | automatically |
| Udap.Identity.Provider | https://udap-idp1.dev.localhost:5055 | automatically |
| Udap.Identity.Provider.2 | https://udap-idp2.dev.localhost:5057 | automatically |
| FhirLabsApi | https://udap-fhirlabs-api.dev.localhost:7016/fhir/r4 | automatically |
| Udap.Certificates.Server (CRLs and AIA) | http://udap-cert-server.dev.localhost:5033 | automatically |
| Udap.Proxy.Server | https://udap-proxy.dev.localhost:7074 | from the dashboard |
| Tefca.Proxy.Server | https://udap-tefca-proxy.dev.localhost:7075 | from the dashboard |
| mTLS.Proxy.Server | https://udap-mtls-proxy.dev.localhost:7057 | from the dashboard |
| Udap.Auth.Server.Admin | http://udap-auth-admin.dev.localhost:5253 | from the dashboard |
| pgAdmin | http://localhost:5050 | automatically |

There is no hosts file to edit. Browsers, curl and .NET resolve any `*.localhost` name to the loopback address themselves. If a name ever stops resolving (some VPN clients, or macOS resolvers), the AppHost logs which one and the hosts-file line that fixes it.

You can still run a single server with `dotnet run --project examples/<Server>`. Its default launch profile uses the same name and port, but it needs a Postgres with its seeded database (see the `Local_*_Migrate` profiles in `migrations/UdapDb.Postgres`).

### Sharing an existing Postgres and pgAdmin

Postgres and pgAdmin are persistent containers, by default `udap-postgres` and `udap-pgadmin`. Their names, volumes and image tags come from [`appsettings.json`](./Udap.AppHost/appsettings.json). To use a Postgres and pgAdmin you already run for other projects, override them in the AppHost's user secrets. Aspire reuses a container whose name and spec match, rather than creating a new one:

```bash
cd examples/Udap.AppHost
dotnet user-secrets set Parameters:postgres-password "<that server's postgres password>"
dotnet user-secrets set Postgres:ContainerName "<postgres container>"
dotnet user-secrets set Postgres:DataVolume "<its data volume>"
dotnet user-secrets set PgAdmin:ContainerName "<pgadmin container>"
dotnet user-secrets set PgAdmin:DataVolume "<its data volume>"
dotnet user-secrets set PgAdmin:ServersFile "<the servers.json file it mounts>"
```

The image tags, volumes and pgAdmin servers file must match how the other project declares the containers, or Aspire recreates them with this spec. The data stays on the volumes, but the other project's next start recreates them back. Set `PgAdmin:Enabled` to `false` to skip pgAdmin.

## Certificates

**HTTPS** uses the ASP.NET dev certificate (above). Nothing to generate.

**UDAP certificates** come from the test PKI generator. Their SAN URIs name the servers' base URLs (for example `https://udap-fhirlabs-api.dev.localhost:7016/fhir/r4`). Their CRL distribution points and AIA URLs point at `http://udap-cert-server.dev.localhost:5033`. After a fresh clone, generate everything once:

```bash
dotnet test _tests/Udap.PKI.Generator
```

To regenerate only the local communities, after changing a host name for example, run these tests and nothing else:

```bash
dotnet test _tests/Udap.PKI.Generator --filter "FullyQualifiedName~MakeCaWithIntermediateUdapForLocalhostCommunity|FullyQualifiedName~MakeNegativeTestCerts|FullyQualifiedName~MakeMultiDomainCertsForSureFhirLabs|FullyQualifiedName~BuildTefcaTestPkiDesk"
```

The SureFhirLabs CA is never replaced once it exists, because deployed servers trust it. Regenerated anchors change what the auth server and identity providers trust, so re-seed their databases afterwards: drop the `Udap.*` databases and start the AppHost again.

## Tiered OAuth

Tiered OAuth works locally. In [UdapEd](https://github.com/JoeShook/UdapEd), enter `https://udap-idp2.dev.localhost:5057` in the **OpenID Connect IdP** field, then sign in as `bob` / `bob` or `alicenewman@example.com` / `alice`. The sign-in page lists the test accounts.

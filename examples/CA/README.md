# Sigil — .NET PKI Management Tool

Sigil is a modern Certificate Authority (CA) and PKI management platform built with .NET. It provides a web-based UI for creating, importing, and managing X.509 certificate hierarchies with support for local and remote (HashiCorp Vault Transit) key storage.

Designed as a lightweight alternative to enterprise CA tools like EJBCA, Sigil is suitable for development, testing, and production PKI workflows — with first-class support for [UDAP](https://www.udap.org/) (Unified Data Access Profiles) healthcare security.

## Features

- **Certificate Explorer** — Hierarchical tree view of Root CA > Intermediate CA > End-entity > CRL chains with detail panel, ASN.1 viewer, and chain validation
- **Certificate Issuance** — Generate Root CAs, Intermediate CAs, and end-entity certificates from configurable templates (RSA + ECDSA)
- **Certificate Templates** — Preset and custom templates controlling key algorithm, extensions, key usage, EKU, CDP, AIA, SANs, and more
- **Import & Auto-Detection** — Drag-and-drop import of .pfx, .cer, .pem, .crl files with automatic role detection and chain matching
- **Chain Validation** — Offline and online validation with CRL checking, AIA issuer resolution, and CDP CRL fetching
- **Renewal** — Re-key (new key pair) and re-sign (same key, new validity) with in-place entity update to preserve child relationships
- **Vault Transit Signing** — Remote signing via HashiCorp Vault Transit secrets engine (private keys never leave Vault)
- **Hybrid Signing** — Issue end-entity certs with local PFX private keys signed by Vault-backed CAs
- **Dashboard** — Community health, expiring/expired certs, overdue CRLs, and deep-link navigation
- **Multi-Community** — Independent PKI namespaces per community (trust domains, tenants, environments)
- **Download API** — REST endpoints for .cer, .pfx, .pem, and .crl downloads

See [FEATURES.md](Sigil/docs/FEATURES.md) for the complete feature list and [ROADMAP.md](ROADMAP.md) for planned phases.

## Architecture

```
examples/CA/
├── Sigil/                  # Blazor Server host (Program.cs, DI, config)
├── Sigil.Common/           # Class library (entities, services, ViewModels)
│   ├── Data/Entities/      # EF Core entities (Community, CaCertificate, IssuedCertificate, Crl, ...)
│   ├── Services/           # Issuance, validation, parsing, import, CRL, ASN.1
│   └── Services/Signing/   # ISigningProvider, LocalSigningProvider, VaultTransitSigningProvider
├── Sigil.UI/               # Razor Class Library (all Blazor components and pages)
├── Sigil.AppHost/           # .NET Aspire orchestrator (Vault + Sigil)
├── Sigil.ServiceDefaults/   # Aspire service defaults (OpenTelemetry, health checks)
└── Sigil.Vault.Hosting/     # Aspire hosting integration for HashiCorp Vault
```

**Key design principle:** `Sigil.Common` has zero UI dependencies and can be consumed by CLI tools, APIs, or test harnesses independently.

**Stack:** .NET 10, Blazor Server (InteractiveServer), FluentUI v4, PostgreSQL, BouncyCastle, Serilog

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [PostgreSQL](https://www.postgresql.org/download/) (15+ recommended)
- [Docker](https://www.docker.com/) (only if using Vault Transit via Aspire)

## Getting Started

### 1. Create the PostgreSQL Database

```sql
CREATE USER sigil WITH PASSWORD 'sigil_pass';
CREATE DATABASE sigil OWNER sigil;
```

### 2. Apply Migrations

```bash
cd examples/CA/Sigil
dotnet ef database update --project ../Sigil.Common
```

Or let Entity Framework apply pending migrations on startup (Sigil calls `Database.MigrateAsync()` at startup).

### 3. Run Sigil (Standalone)

```bash
dotnet run --project examples/CA/Sigil
```

Sigil will be available at **https://localhost:7200**.

All certificate signing uses local PFX-based keys by default.

### 4. Run with Aspire + Vault Transit (Optional)

To enable remote signing via HashiCorp Vault Transit:

```bash
dotnet run --project examples/CA/Sigil.AppHost
```

This starts:
- **Vault** in dev mode (Docker container) with Transit engine and pre-configured signing keys
- **Sigil** with `Signing.Provider=vault-transit` and Vault connection injected via environment variables

The Aspire dashboard provides observability for both services.

## Configuration

### appsettings.json

```json
{
  "ConnectionStrings": {
    "SigilDb": "Host=localhost;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil"
  },
  "Signing": {
    "Provider": "local"
  }
}
```

### Vault Transit (via environment variables or appsettings)

When running via Aspire AppHost, these are set automatically:

| Variable | Description | Default |
|----------|-------------|---------|
| `Signing__Provider` | `local` or `vault-transit` | `local` |
| `Vault__Address` | Vault HTTP address | `http://localhost:8200` |
| `Vault__Token` | Vault authentication token | — |
| `Vault__MountPath` | Transit engine mount path | `transit` |

### Signing Modes

When Vault Transit is configured, the certificate issuance dialog offers a **Key Storage** selector:

| Mode | End-Entity Key | Signing Key | PFX Export |
|------|---------------|-------------|------------|
| **Local (PFX)** | Generated locally | Local CA or Vault CA | Yes |
| **Vault Transit** | Generated in Vault | Vault CA | No (key never leaves Vault) |

This enables a hybrid workflow: Vault-backed CAs can issue end-entity certificates with exportable local private keys.

## Quick Start Workflow

1. **Create a Community** — Go to Communities page, add a new PKI namespace
2. **Create a Root CA** — In Certificate Explorer, click "New Root CA", select a Root CA template
3. **Create an Intermediate CA** — Select the Root CA, click "Issue Certificate", pick an Intermediate CA template
4. **Issue End-Entity Certs** — Select the Intermediate CA, issue client or server certificates
5. **Download** — Use the download buttons for .cer, .pfx, or .pem files
6. **Validate** — Click "Revalidate" or "Validate Online" to verify chain integrity

## Project Dependencies

| Package | Purpose |
|---------|---------|
| Npgsql.EntityFrameworkCore.PostgreSQL | PostgreSQL provider |
| BouncyCastle.Cryptography 2.6.2 | X.509 operations, CRL generation, chain validation |
| Microsoft.FluentUI.AspNetCore.Components | Blazor UI component library |
| Serilog.AspNetCore | Structured logging |
| Aspire.Hosting (optional) | .NET Aspire orchestration |

## License

See [LICENSE](../../LICENSE) in the repository root.

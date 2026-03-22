# Multi-Domain UDAP Metadata Support

## Overview

A UDAP data holder can now serve signed metadata for multiple domains within a single community. Each domain has its own certificate with a Subject Alternative Name (SAN) URI matching that domain's base URL. When a metadata request arrives, the server dynamically selects the correct certificate based on the request URL and signs the metadata with it.

This enables scenarios where an organization operates multiple FHIR endpoints (e.g., different business units, regions, or product lines) under a single trust community, each with its own certificate and base URL.

## What Changed

### Dynamic Metadata Middleware

`UseUdapMetadataServer()` now registers middleware that handles any request path ending with `/.well-known/udap`, regardless of prefix. This replaces the previous endpoint-routing approach that required explicit route registration for each path.

```csharp
// Before: endpoint routing — only served metadata at one fixed path
app.UseUdapMetadataServer("fhir/r4");

// After: middleware — serves metadata at ANY path ending with /.well-known/udap
app.UseUdapMetadataServer();
```

**Placement matters:** Register the middleware before `UseRouting()` and `UseAuthentication()` so metadata requests are handled anonymously before auth or route matching can intercept them.

```csharp
app.UsePathBase(new PathString("/fhir/r4"));
app.UseUdapMetadataServer();   // <-- before routing and auth
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
```

### SAN-Based Certificate Selection

When a community contains multiple certificates, the server selects the certificate whose SAN URI matches the incoming request's base URL. Previously, the server always picked the newest certificate in the community regardless of the URL.

For example, given a community `udap://multihost/` with certificates for:
- `https://fhirlabs.net/one/fhir/r4`
- `https://fhirlabs.net/two/fhir/r4`

A request to `https://fhirlabs.net/one/fhir/r4/.well-known/udap?community=udap://multihost/` returns metadata signed with the certificate whose SAN is `https://fhirlabs.net/one/fhir/r4`.

If no certificate's SAN matches the requested base URL and the community has multiple certificates, the server returns **404**. Single-certificate communities fall back to their one certificate for backward compatibility.

### Issuer/Subject Auto-Resolution

The `Issuer` and `Subject` properties have been removed from `SignedMetadataConfig`. The `iss` and `sub` claims in signed metadata are now always derived from the certificate's SAN that matches the request URL. This eliminates a class of misconfiguration bugs and is consistent with the UDAP specification requirement that the issuer must match a SAN on the signing certificate.

**Configuration change:** Remove any `"Issuer"` and `"Subject"` entries from your `udap.metadata.options*.json` files. They are no longer recognized.

```json
{
  "Community": "udap://example/",
  "SignedMetadataConfig": {
    "AuthorizationEndpoint": "https://auth.example.com/connect/authorize",
    "TokenEndpoint": "https://auth.example.com/connect/token",
    "RegistrationEndpoint": "https://auth.example.com/connect/register"
  }
}
```

## Configuration

### Certificate Store (appsettings.json)

List multiple certificates under a single community. Each certificate's PFX file should contain an end-entity certificate with a unique SAN URI.

```json
{
  "UdapFileCertStoreManifest": {
    "Communities": [
      {
        "Name": "udap://multihost/",
        "IssuedCerts": [
          { "FilePath": "CertStore/issued/domain-one.pfx", "Password": "udap-test" },
          { "FilePath": "CertStore/issued/domain-two.pfx", "Password": "udap-test" },
          { "FilePath": "CertStore/issued/domain-three.pfx", "Password": "udap-test" }
        ]
      }
    ]
  }
}
```

### Metadata Options (udap.metadata.options.json)

A single metadata config entry covers the entire community. The endpoints are shared; the certificate (and therefore issuer) varies per request.

```json
{
  "UdapMetadataConfigs": [
    {
      "Community": "udap://multihost/",
      "SignedMetadataConfig": {
        "AuthorizationEndpoint": "https://auth.example.com/connect/authorize",
        "TokenEndpoint": "https://auth.example.com/connect/token",
        "RegistrationEndpoint": "https://auth.example.com/connect/register"
      }
    }
  ]
}
```

## How It Works

1. A request arrives at `https://example.com/one/fhir/r4/.well-known/udap?community=udap://multihost/`
2. The middleware matches the `/.well-known/udap` suffix and extracts the base URL: `https://example.com/one/fhir/r4`
3. The certificate store is queried for certificates in the `udap://multihost/` community
4. Each certificate's URI SANs (extracted at load time) are compared against the base URL
5. The matching certificate signs the metadata JWT with `iss` and `sub` set to the matched SAN
6. If no certificate matches and the community has multiple certs, **404** is returned

## Performance

Certificate SAN extraction happens once at startup (or when the certificate store reloads). The `IssuedCertificate` class stores SANs as `IReadOnlyList<string>`, so per-request matching is a simple string comparison against an in-memory list — no certificate parsing on each request.

## Breaking Changes

- **`Issuer` and `Subject` removed from `SignedMetadataConfig`** — These properties no longer exist. Remove them from all configuration files. The issuer is always auto-resolved from the certificate's SAN.
- **`UseUdapMetadataServer()` no longer accepts a `prefixRoute` parameter** — The middleware handles all paths dynamically. Remove any prefix arguments.
- **Middleware placement** — `UseUdapMetadataServer()` must be registered before `UseRouting()` and `UseAuthentication()`. Previously it could be placed anywhere since it used endpoint routing.
- **Multi-cert community 404 behavior** — If a community has multiple certificates and none match the request URL, the server now returns 404 instead of picking an arbitrary certificate.

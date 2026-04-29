# Migration Plan: Duende IdentityServer → OpenIddict

## Overview

This document captures the analysis and plan for migrating udap-dotnet from Duende IdentityServer to OpenIddict as the underlying OAuth 2.0 / OpenID Connect server framework.

**Motivation**: OpenIddict is Apache 2.0 licensed with no revenue restrictions. Duende requires a paid license for companies over $1M annual revenue.

**Note**: `Duende.IdentityModel.Client` is a free/open-source component and does not need to be replaced.

---

## Integration Depth Summary

- **177 files** (32% of codebase) reference Duende namespaces
- **462 `using Duende` statements** across the project
- Coupling is architectural — Duende provides the core OAuth2/OIDC pipeline

### Duende NuGet Packages Currently Used (v7.4.6)

| Project | Duende Packages |
|---|---|
| Udap.Server | `Duende.IdentityServer`, `Duende.IdentityServer.AspNetIdentity`, `Duende.IdentityServer.EntityFramework.Storage` |
| Udap.Server.Storage | `Duende.IdentityServer.EntityFramework.Storage`, `Duende.IdentityServer.Storage` |
| Udap.Auth.Server (example) | `Duende.IdentityServer`, `Duende.IdentityServer.EntityFramework` |
| Udap.Identity.Provider (examples) | `Duende.IdentityServer`, `Duende.IdentityServer.EntityFramework` |
| UdapDb.SqlServer / Postgres (migrations) | `Duende.IdentityServer.EntityFramework.Storage` |
| Udap.UI | `Duende.IdentityServer` |

---

## Paradigm Difference: Interface vs Handler Pipeline

### Duende: Interface Implementation

Implement a well-known interface, register in DI.

```csharp
// Duende pattern
public class UdapJwtSecretValidator : ISecretValidator
{
    public UdapJwtSecretValidator(
        IIssuerNameService issuerNameService,
        IReplayCache replayCache,
        IServerUrls urls,
        IdentityServerOptions options,
        TrustChainValidator trustChainValidator, ...)

    public Task<SecretValidationResult> ValidateAsync(
        IEnumerable<Secret> secrets, ParsedSecret parsedSecret)
    {
        // return success/failure result
    }
}

// Registration
services.AddTransient<ISecretValidator, UdapJwtSecretValidator>();
```

### OpenIddict: Event Handler Pipeline

Implement a handler with a static Descriptor controlling ordering/filtering, communicate via context mutation.

```csharp
// OpenIddict pattern
public class UdapJwtSecretHandler : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public UdapJwtSecretHandler(
        TrustChainValidator trustChainValidator, ...)

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<UdapJwtSecretHandler>()
            .SetOrder(ValidateAuthentication.Descriptor.Order + 500)
            .AddFilter<RequireTokenRequest>()
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        // Failure: context.Reject(error, description, uri)
        // Success: just return (or set context properties)
        // Full stop: context.HandleRequest()
    }
}

// Registration
services.AddOpenIddict()
    .AddServer(options =>
    {
        options.AddEventHandler(UdapJwtSecretHandler.Descriptor);
    });
```

### Key Differences

| Aspect | Duende (Interface) | OpenIddict (Handler Pipeline) |
|---|---|---|
| **Contract** | Specific interfaces (`ISecretValidator`, `ISecretParser`, etc.) with typed return values | Always `IOpenIddictServerHandler<TContext>` with `ValueTask HandleAsync(TContext)` |
| **Result** | Return a result object (`SecretValidationResult`) | Mutate the context (`context.Reject(...)` or set properties) |
| **Ordering** | Duende controls when your implementation is called | You control ordering via `SetOrder(int)` |
| **Composition** | One `ISecretValidator` replaces the default | Multiple handlers run in sequence — add alongside built-ins |
| **Scope** | Each interface has a narrow, specific purpose | One pattern fits all — same `HandleAsync` for auth, tokens, discovery, etc. |

---

## Components to Migrate

### Unaffected (No Duende Dependency)

- **Udap.Model** — data models, zero external dependencies
- **Udap.Common** — certificate/trust chain validation, independent of auth server
- **Udap.Metadata.Server** — minimal Duende coupling

### Minimal Changes

- **Udap.Client** — uses `Duende.IdentityModel.Client` which is free/open-source. No migration needed for this dependency.

### Major Migration Required

#### 1. Udap.Server — Custom Duende Interface Implementations

| Component | Duende Interface | Migration Notes |
|---|---|---|
| `UdapJwtBearerClientAssertionSecretParser` | `ISecretParser` | Rewrite as OpenIddict handler for `ExtractTokenRequestContext` or `ProcessAuthenticationContext` |
| `UdapJwtSecretValidator` | `ISecretValidator` | Rewrite as OpenIddict handler for `ValidateTokenRequestContext` |
| `UdapCustomTokenRequestValidator` | `ICustomTokenRequestValidator` | Rewrite as OpenIddict handler — hl7-b2b/TEFCA extension enforcement |
| `UdapTokenResponseGenerator` | Extends `TokenResponseGenerator` | No base class equivalent in OpenIddict — rewrite as `HandleTokenRequestContext` handler |
| `UdapInMemoryResourceStore` | `IResourceStore` | Replace with `IOpenIddictScopeManager` — scope expansion logic stays |
| `UdapDiscoveryEndpoint` | Registered as Duende `Endpoint` | Rewrite as ASP.NET Core middleware or controller |

#### 2. Udap.Server — Middleware (Duende Service Dependencies)

| Component | Duende Dependencies | Migration Notes |
|---|---|---|
| `UdapAuthorizationResponseMiddleware` | `IClientStore`, `IIdentityServerInteractionService` | Replace with `IOpenIddictApplicationManager` + ASP.NET Core equivalents |
| `UdapScopeEnrichmentMiddleware` | Duende scope handling | Adapt to OpenIddict scope model |
| `UdapTokenResponseMiddleware` | Duende token endpoint | Adapt to OpenIddict token pipeline |

#### 3. Udap.Server — Dynamic Client Registration (DCR)

The DCR is custom-built (not Duende's DCR). Key dependencies to replace:

| Dependency | Duende Source | OpenIddict Equivalent |
|---|---|---|
| `IResourceStore` | Duende | `IOpenIddictScopeManager` |
| `IReplayCache` | Duende | Custom implementation or use OpenIddict token storage |
| `IScopeExpander` | Custom (uses `IResourceStore`) | Refactor to use `IOpenIddictScopeManager` |

Core registration logic (JWT validation, certificate chain validation, UDAP spec compliance) is **your own code** and transfers directly.

#### 4. Udap.Server — Tiered OAuth

| Component | Duende Dependencies | Migration Notes |
|---|---|---|
| `TieredOAuthHelpers` | `IIdentityServerInteractionService`, `IUdapClient` | Replace interaction service with OpenIddict equivalents |
| `TieredOAuthAuthenticationHandler` | Duende external auth integration | Adapt to OpenIddict's external auth model |

#### 5. Udap.Server — DI/Configuration

| Component | Notes |
|---|---|
| `UdapServerServiceCollectionExtensions` | Rewrite `AddUdapServer()` to use `services.AddOpenIddict()` builder pattern |
| `UdapBuilderExtensions/UdapCore` | `AddUdapDiscovery()`, `AddUdapResponseGenerators()`, etc. — rewrite for OpenIddict |
| `Additional.cs` | `AddUdapJwtBearerClientAuthentication()` — register OpenIddict handlers instead of Duende interfaces |

#### 6. Udap.Server.Storage — EF Core / Data Layer

**Schema change**: Duende uses `ConfigurationDbContext` + `PersistedGrantDbContext` with Client/Scope/Grant entities. OpenIddict uses 4 tables:

| OpenIddict Table | Purpose |
|---|---|
| `OpenIddictApplications` | Client registration (replaces Duende `Client` entity) |
| `OpenIddictScopes` | Scope definitions |
| `OpenIddictAuthorizations` | Authorization grants |
| `OpenIddictTokens` | Token storage (access, refresh, etc.) |

Key changes:
- `UdapClientRegistrationStore` — currently maps to/from `Duende.IdentityServer.EntityFramework.Entities.Client`. Must be rewritten to use `IOpenIddictApplicationManager`.
- `UdapDbContext` — currently includes `DbSet<Duende...Client>`, `DbSet<PersistedGrant>`, `DbSet<DeviceFlowCodes>`. Replace with OpenIddict entity sets.
- All mappers (`ClientExtensions.cs`) need rewriting for OpenIddict model.
- UDAP-specific entities (Anchor, Intermediate, Community, Certification, TieredClient) are **unaffected** — these are your own tables.

#### 7. Database Migrations

Both `UdapDb.SqlServer` and `UdapDb.Postgres` need new migrations to:
- Drop Duende tables (Client, ClientSecret, ClientScope, ApiResource, ApiScope, PersistedGrant, DeviceFlowCodes, etc.)
- Add OpenIddict tables (Applications, Scopes, Authorizations, Tokens)
- Preserve UDAP-specific tables

#### 8. Example Projects

All example auth servers need their startup rewritten:

| Project | Current Pattern | New Pattern |
|---|---|---|
| `Udap.Auth.Server` | `AddIdentityServer()` + `AddUdapServer()` | `AddOpenIddict()` + `AddUdapServer()` (refactored) |
| `Udap.Identity.Provider` | `AddIdentityServer()` + `AddUdapServerAsIdentityProvider()` | `AddOpenIddict()` + equivalent |
| `Udap.Identity.Provider.2` | Same as above | Same as above |

#### 9. Test Infrastructure

- `UdapAuthServerPipeline` is built around Duende's test infrastructure — needs rewriting
- Integration tests that configure `IdentityServerOptions` need updating
- Test projects referencing `Duende.IdentityServer.Test` need alternatives

#### 10. Udap.UI

- References `Duende.IdentityServer` for login/logout/consent flows
- Needs adaptation for OpenIddict's approach to user interaction

---

## Duende Service → OpenIddict Equivalent Mapping

| Duende Service | OpenIddict Equivalent |
|---|---|
| `IClientStore` | `IOpenIddictApplicationManager` |
| `IResourceStore` | `IOpenIddictScopeManager` |
| `ISecretParser` | `IOpenIddictServerHandler<ExtractTokenRequestContext>` or `ProcessAuthenticationContext` handler |
| `ISecretValidator` | `IOpenIddictServerHandler<ValidateTokenRequestContext>` handler |
| `ICustomTokenRequestValidator` | `IOpenIddictServerHandler<ValidateTokenRequestContext>` handler |
| `ITokenService` | `IOpenIddictTokenManager` |
| `IProfileService` | `IOpenIddictServerHandler<HandleUserInfoRequestContext>` handler or claims transformation |
| `IIdentityServerInteractionService` | No direct equivalent — use ASP.NET Core auth + `IOpenIddictAuthorizationManager` |
| `IIssuerNameService` | `OpenIddictServerOptions.Issuer` or `IHttpContextAccessor` |
| `IReplayCache` | Custom implementation (or leverage token storage) |
| `IServerUrls` | `IHttpContextAccessor` directly |
| `IdentityServerOptions` | `OpenIddictServerOptions` |
| `IScopeParser` | `IOpenIddictScopeManager` |
| `IRefreshTokenService` | Handled internally by OpenIddict |
| `TokenResponseGenerator` | `IOpenIddictServerHandler<HandleTokenRequestContext>` + `ApplyTokenResponseContext` handlers |
| `Endpoint` (Duende endpoint registration) | ASP.NET Core middleware, controllers, or minimal APIs |

---

## What Transfers Directly (No Rewrite)

- All certificate/trust chain validation logic (`TrustChainValidator`, `ICertificateStore`, `ITrustAnchorStore`)
- UDAP JWT assertion parsing and validation (business logic)
- Authorization extension validation (hl7-b2b, TEFCA)
- Scope expansion logic (SMART v2)
- All UDAP model types
- UDAP-specific EF entities (Anchor, Intermediate, Community, etc.)
- Client-side UDAP operations (`Udap.Client`)

---

## Suggested Migration Order

1. **Udap.Server.Storage** — Swap EF entities and stores from Duende to OpenIddict models. This is foundational.
2. **Udap.Server Core** — Rewrite validators/parsers as OpenIddict handlers. Start with `UdapJwtSecretValidator` as a proof of concept.
3. **Udap.Server DCR** — Refactor `UdapDynamicClientRegistrationValidator` to use OpenIddict managers instead of Duende stores.
4. **Udap.Server DI** — Rewrite `AddUdapServer()` extension methods for OpenIddict builder pattern.
5. **Udap.Server Middleware** — Adapt authorization response, scope enrichment, and token response middleware.
6. **Tiered OAuth** — Adapt federated auth flow.
7. **Example Projects** — Update startup configuration.
8. **Database Migrations** — Generate new migrations for SQL Server and PostgreSQL.
9. **Tests** — Rebuild test pipeline and verify all existing test scenarios pass.
10. **Udap.UI** — Adapt login/logout/consent UI flows.

---

## Risk Areas

- **No built-in DCR in OpenIddict** — The custom DCR endpoint must be fully self-hosted (already the case, but Duende infrastructure won't be there as fallback)
- **IIdentityServerInteractionService** — Used in multiple places for error handling and auth flows; no single OpenIddict equivalent
- **Test infrastructure** — Significant test rewrite needed; risk of regression
- **Schema migration** — Existing deployments need data migration from Duende tables to OpenIddict tables

---

## OpenIddict Source Reference

Local source repositories available at `C:\Source\GitHub\openiddict\`:
- `openiddict-core` — Main implementation
- `openiddict-samples` — Reference implementations
- `openiddict-documentation` — Guides and configuration docs

Key source paths:
- `openiddict-core/src/OpenIddict.Abstractions/` — Interfaces and DTOs
- `openiddict-core/src/OpenIddict.Server/` — Server event handlers and pipeline
- `openiddict-core/src/OpenIddict.Server.AspNetCore/` — ASP.NET Core integration
- `openiddict-core/src/OpenIddict.EntityFrameworkCore/` — EF Core stores
- `openiddict-core/src/OpenIddict.EntityFrameworkCore.Models/` — Database entities

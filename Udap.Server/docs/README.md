# Udap.Server

![UDAP logo](https://avatars.githubusercontent.com/u/77421324?s=48&v=4)

## 📦 Nuget Package: [Udap.Server](https://www.nuget.org/packages/Udap.Server)

This package adds UDAP Dynamic Client Registration (DCR) and metadata capabilities to an authorization server built on Duende IdentityServer. It provides the `.well-known/udap` metadata endpoint and the `/connect/register` DCR endpoint as extensions to the IdentityServer pipeline.

> **Note:** Duende IdentityServer requires a [license](https://duendesoftware.com/products/identityserver) for production use above $1M annual revenue.

## Features

- UDAP metadata endpoint (`.well-known/udap`)
- Dynamic Client Registration (create, update, cancel)
- Multi-community trust anchor support
- Authorization Extension Object (AEO) enforcement via `IUdapAuthorizationExtensionValidator`
- Tiered OAuth support

### Profile-Specific Validation

For SSRAA or TEFCA community-specific validation rules, add the corresponding packages:

- [`Udap.Ssraa.Server`](https://www.nuget.org/packages/Udap.Ssraa.Server) — HL7 v3 PurposeOfUse enforcement
- [`Udap.Tefca.Server`](https://www.nuget.org/packages/Udap.Tefca.Server) — TEFCA Exchange Purpose (XP) code validation, SAN matching
- [`Udap.Tefca.Model`](https://www.nuget.org/packages/Udap.Tefca.Model) — TEFCA extension models (`tefca-ias`, `tefca_smart`)

## Full Example

Below is a full example. See also the [Udap.Auth.Server](../../examples/Udap.Auth.Server/) example project.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityServer()
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));
    })
    .AddResourceStore<ResourceStore>()
    .AddClientStore<ClientStore>()
    .AddTestUsers(TestUsers.Users)
    .AddUdapServer(
        options =>
        {
            var udapServerOptions = builder.Configuration.GetOption<ServerSettings>("ServerSettings");
            options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
            options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
            options.ForceStateParamOnAuthorizationCode = udapServerOptions
                .ForceStateParamOnAuthorizationCode;
        },
        options =>
            options.UdapDbContext = b =>
                b.UseSqlite(connectionString,
                    dbOpts =>
                        dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName)),
        baseUrl: "https://localhost:5002/connect/register"
    );

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();

app.UseUdapServer();
app.UseIdentityServer();

app.UseAuthorization();
app.MapRazorPages().RequireAuthorization();

app.Run();
```

## Database Configuration

EF Core migration projects are available for both database providers:

- [UdapDb.SqlServer](../../migrations/UdapDb.SqlServer/) — SQL Server migrations
- [UdapDb.Postgres](../../migrations/UdapDb.Postgres/) — PostgreSQL migrations

These projects create all UDAP and Duende IdentityServer tables and seed data needed for running local tests. See `SeedData.cs` for details.

## Examples

- [Udap.Auth.Server](../../examples/Udap.Auth.Server/)
- [Udap.Auth.Server Deployed](https://securedcontrols.net/.well-known/udap)

---

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org.

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigil.Vault.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

// Vault (dev mode) with Transit engine + signing keys
var vault = builder.AddVaultDev("vault")
    .WithTransitEngine(
        new TransitKeySpec("sigil-rsa-4096", "rsa-4096"),
        new TransitKeySpec("sigil-ecdsa-p384", "ecdsa-p384"));

// Sigil uses its own PostgreSQL connection string from appsettings.json
builder.AddProject<Projects.Sigil>("sigil")
    .WithReference(vault)
    .WithEnvironment("Vault__Address", vault.Resource.PrimaryEndpoint)
    .WithEnvironment("Vault__Token", "root-token")
    .WithEnvironment("Signing__Provider", "vault-transit");

builder.Build().Run();

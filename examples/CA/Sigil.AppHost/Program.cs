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

// Sigil hosting mode: "project" (default), "docker", or "docker-gcp"
// Set via env var Sigil__HostMode in launch profile.
var hostMode = builder.Configuration["Sigil:HostMode"]?.ToLowerInvariant() ?? "project";

IResourceBuilder<IResourceWithEndpoints> sigil;

switch (hostMode)
{
    case "docker-gcp":
    case "docker":
    {
        var dockerfile = hostMode == "docker-gcp" ? "Sigil/Dockerfile.gcp" : "Sigil/Dockerfile";

        var dockerResource = builder.AddDockerfile("sigil", "..", dockerfile)
            .WithHttpEndpoint(port: 5200, targetPort: 5200)
            .WithHttpsEndpoint(port: 7200, targetPort: 7200)
            .WithHttpsCertificateConfiguration(ctx =>
            {
                // Aspire injects its trusted dev cert — Kestrel picks it up via these env vars
                if (ctx.Password is null)
                {
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Path"] = ctx.CertificatePath;
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__KeyPath"] = ctx.KeyPath;
                }
                else
                {
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Path"] = ctx.PfxPath;
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Password"] = ctx.Password;
                }
                return Task.CompletedTask;
            })
            .WithEnvironment("ASPNETCORE_URLS", "https://+:7200;http://+:5200")
            .WithReference(vault)
            .WithEnvironment("ConnectionStrings__SigilDb", "Host=host.docker.internal;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil")
            .WithEnvironment("Vault__Address", vault.Resource.PrimaryEndpoint)
            .WithEnvironment("Vault__Token", "root-token")
            .WithEnvironment("Signing__Provider", "vault-transit");

        if (hostMode == "docker-gcp")
            dockerResource.WithVolume("sigil-gcloud-config", "/root/.config/gcloud");

        sigil = dockerResource;
        break;
    }

    default: // "project"
        sigil = builder.AddProject<Projects.Sigil>("sigil")
            .WithReference(vault)
            .WithEnvironment("Vault__Address", vault.Resource.PrimaryEndpoint)
            .WithEnvironment("Vault__Token", "root-token")
            .WithEnvironment("Signing__Provider", "vault-transit");
        break;
}

builder.Build().Run();

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Eventing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace Sigil.Vault.Hosting;

public static class VaultResourceBuilderExtensions
{
    /// <summary>
    /// Adds a HashiCorp Vault container in dev mode.
    /// Dev mode starts Vault unsealed with an in-memory backend — suitable for development and testing.
    /// </summary>
    public static IResourceBuilder<VaultResource> AddVaultDev(
        this IDistributedApplicationBuilder builder,
        string name,
        string rootToken = "root-token",
        int? port = null)
    {
        var resource = new VaultResource(name) { RootToken = rootToken };

        var health = builder.Services.AddHealthChecks();

        return builder.AddResource(resource)
            .WithContainerName($"vault-{name}")
            .WithAnnotation(new ContainerImageAnnotation
            {
                Image = VaultContainerImageTags.Image,
                Tag = VaultContainerImageTags.Tag,
                Registry = VaultContainerImageTags.Registry
            })
            .WithContainerRuntimeArgs("--cap-add", "IPC_LOCK")
            .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", rootToken)
            .WithEnvironment("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .WithEndpoint(
                port ?? VaultResource.DefaultPort,
                VaultResource.DefaultPort,
                name: VaultResource.HttpEndpointName,
                scheme: "http")
            .WithHealthCheck(health, name);
    }

    /// <summary>
    /// Configures the Transit secrets engine with the specified signing keys.
    /// Keys are created automatically after Vault starts and is healthy.
    /// </summary>
    public static IResourceBuilder<VaultResource> WithTransitEngine(
        this IResourceBuilder<VaultResource> builder,
        params TransitKeySpec[] keys)
    {
        builder.Resource.TransitKeys.AddRange(keys);

        // Subscribe to the AfterResourcesCreated event to configure Transit
        builder.ApplicationBuilder.Eventing.Subscribe<AfterResourcesCreatedEvent>(
            async (@event, ct) =>
            {
                var vaultResources = @event.Model.Resources.OfType<VaultResource>().ToList();

                foreach (var vault in vaultResources)
                {
                    if (vault.TransitKeys.Count == 0) continue;

                    var logger = @event.Services.GetRequiredService<ILogger<VaultResource>>();

                    try
                    {
                        // Wait for the resource to be healthy
                        var notificationService = @event.Services
                            .GetRequiredService<ResourceNotificationService>();
                        await notificationService.WaitForResourceHealthyAsync(
                            vault.Name, ct);

                        // Build the Vault address from the allocated endpoint
                        var endpoint = vault.GetEndpoint(VaultResource.HttpEndpointName);
                        var vaultAddress = $"http://localhost:{endpoint.Port}";

                        await VaultTransitConfigurator.ConfigureTransitAsync(
                            vaultAddress, vault.RootToken, vault.TransitKeys, logger, ct);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex,
                            "Failed to configure Vault Transit for resource '{Name}'",
                            vault.Name);
                    }
                }
            });

        return builder;
    }

    private static IResourceBuilder<VaultResource> WithHealthCheck(
        this IResourceBuilder<VaultResource> builder,
        IHealthChecksBuilder health,
        string name)
    {
        health.AddUrlGroup(
            _ => new Uri($"http://localhost:{VaultResource.DefaultPort}/v1/sys/health"),
            $"{name}-vault-health",
            HealthStatus.Unhealthy);

        return builder.WithHealthCheck($"{name}-vault-health");
    }
}

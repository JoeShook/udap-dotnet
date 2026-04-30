#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace Sigil.Vault.Hosting;

/// <summary>
/// Configures the Vault Transit secrets engine after the Vault container is healthy.
/// Called via Aspire eventing (AfterResourcesCreatedEvent).
/// </summary>
internal static class VaultTransitConfigurator
{
    internal static async Task ConfigureTransitAsync(
        string vaultAddress,
        string rootToken,
        List<TransitKeySpec> keys,
        ILogger logger,
        CancellationToken ct)
    {
        using var client = new HttpClient { BaseAddress = new Uri(vaultAddress) };
        client.DefaultRequestHeaders.Add("X-Vault-Token", rootToken);

        // Enable Transit secrets engine
        logger.LogInformation("Enabling Vault Transit engine at {Address}", vaultAddress);

        var mountResponse = await client.PostAsJsonAsync(
            "/v1/sys/mounts/transit",
            new { type = "transit" },
            ct);

        if (mountResponse.IsSuccessStatusCode)
        {
            logger.LogInformation("Transit engine mounted successfully");
        }
        else if ((int)mountResponse.StatusCode == 400)
        {
            // Already mounted — not an error
            logger.LogInformation("Transit engine already mounted");
        }
        else
        {
            var body = await mountResponse.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Transit mount returned {Status}: {Body}",
                mountResponse.StatusCode, body);
        }

        // Create signing keys
        foreach (var key in keys)
        {
            logger.LogInformation("Creating Transit key '{Name}' (type: {Type})", key.Name, key.Type);

            var keyResponse = await client.PostAsJsonAsync(
                $"/v1/transit/keys/{key.Name}",
                new { type = key.Type },
                ct);

            if (keyResponse.IsSuccessStatusCode)
            {
                logger.LogInformation("Transit key '{Name}' created", key.Name);
            }
            else
            {
                var body = await keyResponse.Content.ReadAsStringAsync(ct);
                logger.LogWarning("Transit key '{Name}' creation returned {Status}: {Body}",
                    key.Name, keyResponse.StatusCode, body);
            }
        }
    }
}

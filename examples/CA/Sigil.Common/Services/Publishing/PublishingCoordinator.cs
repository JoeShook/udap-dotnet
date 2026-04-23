#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging;

namespace Sigil.Common.Services.Publishing;

/// <summary>
/// Routes CRL and certificate publishing requests to the appropriate provider
/// based on the domain (Authority) portion of the target URL.
/// Multiple providers can be active simultaneously for different domains.
/// </summary>
public class PublishingCoordinator
{
    private readonly Dictionary<string, IPublishingProvider> _providersByDomain;
    private readonly ILogger<PublishingCoordinator> _logger;

    public PublishingCoordinator(
        Dictionary<string, IPublishingProvider> providersByDomain,
        ILogger<PublishingCoordinator> logger)
    {
        _providersByDomain = providersByDomain;
        _logger = logger;
    }

    /// <summary>
    /// Publishes a CRL to the location specified by the CDP URL.
    /// The URL domain is used to select the publishing provider.
    /// Publishing failures are logged but do not throw.
    /// </summary>
    public async Task PublishCrlAsync(string? cdpUrl, byte[] crlBytes, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(cdpUrl)) return;

        if (!Uri.TryCreate(cdpUrl, UriKind.Absolute, out var uri))
        {
            _logger.LogWarning("Invalid CDP URL: '{CdpUrl}'", cdpUrl);
            return;
        }

        if (!_providersByDomain.TryGetValue(uri.Authority, out var provider))
        {
            _logger.LogWarning(
                "No publishing provider configured for domain '{Domain}'. Configured domains: [{Domains}]",
                uri.Authority, string.Join(", ", _providersByDomain.Keys));
            return;
        }

        try
        {
            await provider.PublishCrlAsync(uri, crlBytes, ct);
            _logger.LogInformation("Published CRL to {Url} via {ProviderType} provider", cdpUrl, provider.ProviderType);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish CRL to {Url} via {ProviderType} provider", cdpUrl, provider.ProviderType);
        }
    }

    /// <summary>
    /// Publishes a certificate to the location specified by the AIA URL.
    /// The URL domain is used to select the publishing provider.
    /// Publishing failures are logged but do not throw.
    /// </summary>
    public async Task PublishCertificateAsync(string? aiaUrl, byte[] certBytes, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(aiaUrl)) return;

        if (!Uri.TryCreate(aiaUrl, UriKind.Absolute, out var uri))
        {
            _logger.LogWarning("Invalid AIA URL: '{AiaUrl}'", aiaUrl);
            return;
        }

        if (!_providersByDomain.TryGetValue(uri.Authority, out var provider))
        {
            _logger.LogWarning(
                "No publishing provider configured for domain '{Domain}'. Configured domains: [{Domains}]",
                uri.Authority, string.Join(", ", _providersByDomain.Keys));
            return;
        }

        try
        {
            await provider.PublishCertificateAsync(uri, certBytes, ct);
            _logger.LogInformation("Published certificate to {Url} via {ProviderType} provider", aiaUrl, provider.ProviderType);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish certificate to {Url} via {ProviderType} provider", aiaUrl, provider.ProviderType);
        }
    }
}

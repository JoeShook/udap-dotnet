#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.X509;
using ZiggyCreatures.Caching.Fusion;

namespace Udap.Common.Certificates;

/// <summary>
/// FusionCache-backed cache for AIA-fetched intermediate certificates and CRLs.
/// Consumers can configure the named cache (<see cref="CacheName"/>) with any backend:
/// in-memory (default), Redis, or hybrid.
/// </summary>
public class CertificateDownloadCache : ICertificateDownloadCache
{
    /// <summary>
    /// Named cache identifier. Register with <c>services.AddFusionCache("UdapCertificates")</c>.
    /// </summary>
    public const string CacheName = "UdapCertificates";

    private const string IntermediatePrefix = "intermediate:";
    private const string CrlPrefix = "crl:";

    private readonly ConcurrentDictionary<string, byte> _intermediateKeys = new();
    private readonly ConcurrentDictionary<string, byte> _crlKeys = new();

    private readonly IFusionCache _cache;
    private readonly HttpClient _httpClient;
    private readonly ILogger<CertificateDownloadCache> _logger;
    private readonly TimeSpan _defaultCrlTtl;

    public CertificateDownloadCache(
        IFusionCacheProvider cacheProvider,
        HttpClient httpClient,
        ILogger<CertificateDownloadCache> logger,
        TimeSpan? defaultCrlTtl = null)
    {
        _cache = cacheProvider.GetCache(CacheName);
        _httpClient = httpClient;
        _logger = logger;
        _defaultCrlTtl = defaultCrlTtl ?? TimeSpan.FromHours(12);
    }

    /// <inheritdoc />
    public async Task<X509Certificate2?> GetIntermediateCertificateAsync(string url, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{IntermediatePrefix}{url}";

        var result = await _cache.TryGetAsync<byte[]>(cacheKey, token: cancellationToken);
        if (result.HasValue)
        {
            return new X509Certificate2(result.Value);
        }

        try
        {
            _logger.LogDebug("Downloading intermediate certificate from {Url}", url);
            var data = await _httpClient.GetByteArrayAsync(url, cancellationToken);
            var cert = new X509Certificate2(data);

            var timeToExpiry = cert.NotAfter.ToUniversalTime() - DateTime.UtcNow;
            var options = new FusionCacheEntryOptions();
            if (timeToExpiry > TimeSpan.Zero)
            {
                options.Duration = timeToExpiry;
            }

            await _cache.SetAsync(cacheKey, data, options, cancellationToken);
            _intermediateKeys.TryAdd(url, 0);

            return cert;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download intermediate certificate from {Url}", url);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<X509Crl?> GetCrlAsync(string url, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{CrlPrefix}{url}";

        var result = await _cache.TryGetAsync<byte[]>(cacheKey, token: cancellationToken);
        if (result.HasValue)
        {
            return new X509CrlParser().ReadCrl(result.Value);
        }

        try
        {
            _logger.LogDebug("Downloading CRL from {Url}", url);
            var data = await _httpClient.GetByteArrayAsync(url, cancellationToken);

            var crl = new X509CrlParser().ReadCrl(data);
            var expiry = crl.NextUpdate ?? DateTime.UtcNow.Add(_defaultCrlTtl);
            var timeToExpiry = expiry.ToUniversalTime() - DateTime.UtcNow;

            var options = new FusionCacheEntryOptions();
            if (timeToExpiry > TimeSpan.Zero)
            {
                options.Duration = timeToExpiry;
            }

            await _cache.SetAsync(cacheKey, data, options, cancellationToken);
            _crlKeys.TryAdd(url, 0);

            return crl;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download CRL from {Url}", url);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task RemoveIntermediateAsync(string url, CancellationToken cancellationToken = default)
    {
        await _cache.RemoveAsync($"{IntermediatePrefix}{url}", token: cancellationToken);
        _intermediateKeys.TryRemove(url, out _);
        _logger.LogDebug("Removed cached intermediate certificate for {Url}", url);
    }

    /// <inheritdoc />
    public async Task RemoveCrlAsync(string url, CancellationToken cancellationToken = default)
    {
        await _cache.RemoveAsync($"{CrlPrefix}{url}", token: cancellationToken);
        _crlKeys.TryRemove(url, out _);
        _logger.LogDebug("Removed cached CRL for {Url}", url);
    }

    /// <inheritdoc />
    public async Task RemoveAllIntermediatesAsync(CancellationToken cancellationToken = default)
    {
        foreach (var url in _intermediateKeys.Keys)
        {
            await _cache.RemoveAsync($"{IntermediatePrefix}{url}", token: cancellationToken);
        }

        _intermediateKeys.Clear();
        _logger.LogInformation("Removed all cached intermediate certificates");
    }

    /// <inheritdoc />
    public async Task RemoveAllCrlsAsync(CancellationToken cancellationToken = default)
    {
        foreach (var url in _crlKeys.Keys)
        {
            await _cache.RemoveAsync($"{CrlPrefix}{url}", token: cancellationToken);
        }

        _crlKeys.Clear();
        _logger.LogInformation("Removed all cached CRLs");
    }

    /// <inheritdoc />
    public async Task RemoveAllAsync(CancellationToken cancellationToken = default)
    {
        await RemoveAllIntermediatesAsync(cancellationToken);
        await RemoveAllCrlsAsync(cancellationToken);
        _logger.LogInformation("Certificate download cache cleared");
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string> CachedIntermediateUrls => _intermediateKeys.Keys.ToList().AsReadOnly();

    /// <inheritdoc />
    public IReadOnlyCollection<string> CachedCrlUrls => _crlKeys.Keys.ToList().AsReadOnly();
}

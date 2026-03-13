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

namespace Udap.Common.Certificates;

/// <summary>
/// In-memory cache for AIA-fetched intermediate certificates and CRLs.
/// Provides full control over cache lifetime — no OS-level caching involved.
/// Thread-safe and flushable at any time without process restart.
/// </summary>
public class CertificateDownloadCache
{
    private readonly ConcurrentDictionary<string, CachedCrl> _crlCache = new();
    private readonly ConcurrentDictionary<string, CachedIntermediate> _intermediateCache = new();
    private readonly HttpClient _httpClient;
    private readonly ILogger<CertificateDownloadCache> _logger;
    private readonly TimeSpan _defaultCrlTtl;

    public CertificateDownloadCache(
        HttpClient httpClient,
        ILogger<CertificateDownloadCache> logger,
        TimeSpan? defaultCrlTtl = null)
    {
        _httpClient = httpClient;
        _logger = logger;
        _defaultCrlTtl = defaultCrlTtl ?? TimeSpan.FromHours(12);
    }

    /// <summary>
    /// Flush all cached CRLs and intermediate certificates immediately.
    /// Takes effect instantly — no process restart required.
    /// </summary>
    public void Flush()
    {
        _crlCache.Clear();
        _intermediateCache.Clear();
        _logger.LogInformation("Certificate download cache flushed");
    }

    /// <summary>
    /// Flush only CRL cache entries.
    /// </summary>
    public void FlushCrls()
    {
        _crlCache.Clear();
        _logger.LogInformation("CRL cache flushed");
    }

    /// <summary>
    /// Flush only intermediate certificate cache entries.
    /// </summary>
    public void FlushIntermediates()
    {
        _intermediateCache.Clear();
        _logger.LogInformation("Intermediate certificate cache flushed");
    }

    /// <summary>
    /// Download an intermediate certificate from the given AIA URL, with caching.
    /// </summary>
    public async Task<X509Certificate2?> GetIntermediateCertificateAsync(string url, CancellationToken cancellationToken = default)
    {
        if (_intermediateCache.TryGetValue(url, out var cached) && !cached.IsExpired)
        {
            return cached.Certificate;
        }

        try
        {
            _logger.LogDebug("Downloading intermediate certificate from {Url}", url);
            var bytes = await _httpClient.GetByteArrayAsync(url, cancellationToken);
            var cert = new X509Certificate2(bytes);
            _intermediateCache[url] = new CachedIntermediate(cert);
            return cert;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download intermediate certificate from {Url}", url);
            return null;
        }
    }

    /// <summary>
    /// Download a CRL from the given CDP URL, with caching.
    /// Respects the CRL's nextUpdate field for cache expiry.
    /// </summary>
    public async Task<X509Crl?> GetCrlAsync(string url, CancellationToken cancellationToken = default)
    {
        if (_crlCache.TryGetValue(url, out var cached) && !cached.IsExpired)
        {
            return cached.Crl;
        }

        try
        {
            _logger.LogDebug("Downloading CRL from {Url}", url);
            var bytes = await _httpClient.GetByteArrayAsync(url, cancellationToken);
            var crlParser = new X509CrlParser();
            var crl = crlParser.ReadCrl(bytes);

            var expiry = crl.NextUpdate ?? DateTime.UtcNow.Add(_defaultCrlTtl);

            _crlCache[url] = new CachedCrl(crl, expiry);
            return crl;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download CRL from {Url}", url);
            return null;
        }
    }

    /// <summary>
    /// Number of cached intermediate certificates.
    /// </summary>
    public int IntermediateCacheCount => _intermediateCache.Count;

    /// <summary>
    /// Number of cached CRLs.
    /// </summary>
    public int CrlCacheCount => _crlCache.Count;

    private class CachedIntermediate
    {
        public CachedIntermediate(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }

        public X509Certificate2 Certificate { get; }
        public bool IsExpired => DateTime.UtcNow >= Certificate.NotAfter.ToUniversalTime();
    }

    private class CachedCrl
    {
        public CachedCrl(X509Crl crl, DateTime expiresUtc)
        {
            Crl = crl;
            ExpiresUtc = expiresUtc;
        }

        public X509Crl Crl { get; }
        public DateTime ExpiresUtc { get; }
        public bool IsExpired => DateTime.UtcNow >= ExpiresUtc;
    }
}

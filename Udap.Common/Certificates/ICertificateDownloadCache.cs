#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;

namespace Udap.Common.Certificates;

/// <summary>
/// Cache for AIA-fetched intermediate certificates and CRLs.
/// Backed by FusionCache, allowing consumers to configure in-memory,
/// distributed (Redis), or hybrid caching strategies.
/// </summary>
public interface ICertificateDownloadCache
{
    /// <summary>
    /// Download an intermediate certificate from the given AIA URL, with caching.
    /// </summary>
    Task<X509Certificate2?> GetIntermediateCertificateAsync(string url, CancellationToken cancellationToken = default);

    /// <summary>
    /// Download a CRL from the given CDP URL, with caching.
    /// Respects the CRL's nextUpdate field for cache expiry.
    /// </summary>
    Task<X509Crl?> GetCrlAsync(string url, CancellationToken cancellationToken = default);

    /// <summary>
    /// Remove a specific intermediate certificate from the cache by its AIA URL.
    /// </summary>
    Task RemoveIntermediateAsync(string url, CancellationToken cancellationToken = default);

    /// <summary>
    /// Remove a specific CRL from the cache by its CDP URL.
    /// </summary>
    Task RemoveCrlAsync(string url, CancellationToken cancellationToken = default);
}

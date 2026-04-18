#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Services.Publishing;

/// <summary>
/// Abstraction for publishing CRLs and certificates to external locations.
/// Implementations handle specific storage backends (file system, GCS, etc.).
/// The provider receives the full target URL and extracts the path to determine
/// where to write the content.
/// </summary>
public interface IPublishingProvider
{
    /// <summary>
    /// Provider type identifier for diagnostics/logging (e.g., "filesystem", "gcp").
    /// </summary>
    string ProviderType { get; }

    /// <summary>
    /// Publishes a DER-encoded CRL to the location derived from the target URL.
    /// </summary>
    Task PublishCrlAsync(Uri targetUrl, byte[] crlBytes, CancellationToken ct = default);

    /// <summary>
    /// Publishes a certificate (DER or PEM) to the location derived from the target URL.
    /// </summary>
    Task PublishCertificateAsync(Uri targetUrl, byte[] certBytes, CancellationToken ct = default);
}

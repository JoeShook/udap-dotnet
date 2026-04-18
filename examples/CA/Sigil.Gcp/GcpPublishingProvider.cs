#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Google.Cloud.Storage.V1;
using Microsoft.Extensions.Logging;
using Sigil.Common.Services.Publishing;

namespace Sigil.Gcp;

/// <summary>
/// Publishes CRLs and certificates to a Google Cloud Storage bucket.
/// Uses Application Default Credentials (ADC) for authentication.
/// The object key is derived from the URL path.
/// </summary>
public sealed class GcpPublishingProvider : IPublishingProvider
{
    public string ProviderType => "gcp";

    private readonly GcpPublisherOptions _options;
    private readonly ILogger<GcpPublishingProvider> _logger;
    private readonly Lazy<StorageClient> _storageClient;

    public GcpPublishingProvider(GcpPublisherOptions options, ILogger<GcpPublishingProvider> logger)
    {
        _options = options;
        _logger = logger;
        _storageClient = new Lazy<StorageClient>(() => StorageClient.Create());
    }

    public async Task PublishCrlAsync(Uri targetUrl, byte[] crlBytes, CancellationToken ct = default)
    {
        var objectName = ExtractObjectName(targetUrl);
        await UploadAsync(objectName, crlBytes, "application/pkix-crl", ct);
        _logger.LogInformation("Published CRL to gs://{Bucket}/{Object} ({Bytes} bytes)",
            _options.BucketName, objectName, crlBytes.Length);
    }

    public async Task PublishCertificateAsync(Uri targetUrl, byte[] certBytes, CancellationToken ct = default)
    {
        var objectName = ExtractObjectName(targetUrl);
        var contentType = objectName.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)
            ? "application/pkix-crl"
            : "application/x-x509-ca-cert";
        await UploadAsync(objectName, certBytes, contentType, ct);
        _logger.LogInformation("Published certificate to gs://{Bucket}/{Object} ({Bytes} bytes)",
            _options.BucketName, objectName, certBytes.Length);
    }

    private async Task UploadAsync(string objectName, byte[] bytes, string contentType, CancellationToken ct)
    {
        using var stream = new MemoryStream(bytes);
        await _storageClient.Value.UploadObjectAsync(
            _options.BucketName,
            objectName,
            contentType,
            stream,
            cancellationToken: ct);
    }

    private static string ExtractObjectName(Uri targetUrl)
    {
        // Strip leading slash to get the GCS object key
        return targetUrl.AbsolutePath.TrimStart('/');
    }
}

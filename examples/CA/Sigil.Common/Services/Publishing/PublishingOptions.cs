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
/// Configuration for the publishing system. Each entry in <see cref="Providers"/>
/// maps a URL domain (with optional port) to a specific provider configuration.
/// When a CRL or certificate is published, the domain portion of the CDP/AIA URL
/// is used to look up the matching provider.
/// </summary>
public class PublishingOptions
{
    public List<PublishingProviderConfig> Providers { get; set; } = new();
}

public class PublishingProviderConfig
{
    /// <summary>
    /// The URL domain (with optional port) this provider handles,
    /// e.g. "host.docker.internal:5033" or "storage.googleapis.com".
    /// </summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    /// Provider type: "filesystem" or "gcp".
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Base directory for the filesystem provider.
    /// The URL path is appended to this to determine the file location.
    /// </summary>
    public string? BaseDirectory { get; set; }

    /// <summary>
    /// GCS bucket name for the GCP provider.
    /// </summary>
    public string? BucketName { get; set; }
}

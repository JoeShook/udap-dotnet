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
using Sigil.Common.Services.Publishing;

namespace Sigil.FileSystem;

/// <summary>
/// Publishes CRLs and certificates to the local file system.
/// The URL path is extracted and combined with the configured base directory
/// to determine the file location. Directories are created as needed.
/// </summary>
public sealed class FileSystemPublishingProvider : IPublishingProvider
{
    public string ProviderType => "filesystem";

    private readonly string _baseDirectory;
    private readonly ILogger<FileSystemPublishingProvider> _logger;

    public FileSystemPublishingProvider(string baseDirectory, ILogger<FileSystemPublishingProvider> logger)
    {
        _baseDirectory = Path.GetFullPath(baseDirectory);
        _logger = logger;
    }

    public async Task PublishCrlAsync(Uri targetUrl, byte[] crlBytes, CancellationToken ct = default)
    {
        var fullPath = ResolvePath(targetUrl);
        await WriteFileAsync(fullPath, crlBytes, ct);
        _logger.LogInformation("Published CRL to {Path} ({Bytes} bytes)", fullPath, crlBytes.Length);
    }

    public async Task PublishCertificateAsync(Uri targetUrl, byte[] certBytes, CancellationToken ct = default)
    {
        var fullPath = ResolvePath(targetUrl);
        await WriteFileAsync(fullPath, certBytes, ct);
        _logger.LogInformation("Published certificate to {Path} ({Bytes} bytes)", fullPath, certBytes.Length);
    }

    private string ResolvePath(Uri targetUrl)
    {
        var relativePath = targetUrl.AbsolutePath.TrimStart('/');
        return Path.GetFullPath(Path.Combine(_baseDirectory, relativePath));
    }

    private static async Task WriteFileAsync(string fullPath, byte[] bytes, CancellationToken ct)
    {
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        // Write to temp file first, then move for atomicity
        var tempPath = fullPath + ".tmp";
        await File.WriteAllBytesAsync(tempPath, bytes, ct);
        File.Move(tempPath, fullPath, overwrite: true);
    }
}

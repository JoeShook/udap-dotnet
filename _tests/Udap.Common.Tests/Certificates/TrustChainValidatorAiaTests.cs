#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.X509;
using Udap.Common.Certificates;
using Udap.Model.Statement;

namespace Udap.Common.Tests.Certificates;

/// <summary>
/// The allowAiaDownload overload of <see cref="TrustChainValidator.IsTrustedCertificateAsync(string, X509Certificate2, X509Certificate2Collection?, X509Certificate2Collection, IEnumerable{Udap.Common.Models.Anchor}?, bool, CancellationToken)"/>.
/// </summary>
public class TrustChainValidatorAiaTests
{
    [Fact]
    public async Task AiaAllowed_CompletesChainFromDownload()
    {
        var (leaf, intermediate, anchor) = LoadChain();
        var cache = new RecordingDownloadCache(intermediate);

        var result = await Validator(cache).IsTrustedCertificateAsync(
            "client", leaf, null, new X509Certificate2Collection(anchor), null, allowAiaDownload: true);

        Assert.True(result.IsValid);
        Assert.Single(cache.Urls);
    }

    [Fact]
    public async Task AiaDisallowed_DoesNotDownload_AndFailsWithoutIntermediate()
    {
        var (leaf, intermediate, anchor) = LoadChain();
        var cache = new RecordingDownloadCache(intermediate);

        var result = await Validator(cache).IsTrustedCertificateAsync(
            "client", leaf, null, new X509Certificate2Collection(anchor), null, allowAiaDownload: false);

        Assert.False(result.IsValid);
        Assert.Empty(cache.Urls);
    }

    [Fact]
    public async Task AiaDisallowed_ValidatesWithSuppliedIntermediate()
    {
        var (leaf, intermediate, anchor) = LoadChain();
        var cache = new RecordingDownloadCache(intermediate);

        var result = await Validator(cache).IsTrustedCertificateAsync(
            "client", leaf, new X509Certificate2Collection(intermediate), new X509Certificate2Collection(anchor), null, allowAiaDownload: false);

        Assert.True(result.IsValid);
        Assert.Equal(3, result.ChainElements.Count);
        Assert.Empty(cache.Urls);
    }

    private static TrustChainValidator Validator(ICertificateDownloadCache cache) =>
        new(TrustChainValidator.DefaultProblemFlags, false, NullLogger<TrustChainValidator>.Instance, cache);

    private static (X509Certificate2 Leaf, X509Certificate2 Intermediate, X509Certificate2 Anchor) LoadChain()
    {
#if NET9_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
#else
        var collection = new X509Certificate2Collection();
        collection.Import("CertStore/issued/fhirlabs.net.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
#endif
        var leaf = collection.Single(c => !X5cChain.IsCertificateAuthority(c));
        var intermediate = collection.Single(c => X5cChain.IsCertificateAuthority(c) && !X5cChain.IsSelfSigned(c));
        var anchor = collection.Single(X5cChain.IsSelfSigned);

        return (leaf, intermediate, anchor);
    }

    private sealed class RecordingDownloadCache(X509Certificate2 intermediate) : ICertificateDownloadCache
    {
        public List<string> Urls { get; } = [];

        public Task<X509Certificate2?> GetIntermediateCertificateAsync(string url, CancellationToken cancellationToken = default)
        {
            Urls.Add(url);
            return Task.FromResult<X509Certificate2?>(intermediate);
        }

        public Task<X509Crl?> GetCrlAsync(string url, CancellationToken cancellationToken = default) => Task.FromResult<X509Crl?>(null);

        public Task RemoveIntermediateAsync(string url, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RemoveCrlAsync(string url, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

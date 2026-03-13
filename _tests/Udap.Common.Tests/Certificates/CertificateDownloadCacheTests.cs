#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Udap.Common.Certificates;
using Xunit.Abstractions;
using ZiggyCreatures.Caching.Fusion;

namespace Udap.Common.Tests.Certificates;

public class CertificateDownloadCacheTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public CertificateDownloadCacheTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task GetIntermediateCertificateAsync_CachesOnFirstCall_ReturnsCachedOnSecond()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();

        handler.SetResponse("https://example.com/intermediate.cer", certBytes);

        var cert1 = await cache.GetIntermediateCertificateAsync("https://example.com/intermediate.cer");
        cert1.Should().NotBeNull();
        handler.CallCount("https://example.com/intermediate.cer").Should().Be(1);

        var cert2 = await cache.GetIntermediateCertificateAsync("https://example.com/intermediate.cer");
        cert2.Should().NotBeNull();
        handler.CallCount("https://example.com/intermediate.cer").Should().Be(1, "second call should come from cache");

        cert1!.Thumbprint.Should().Be(cert2!.Thumbprint);

        cache.CachedIntermediateUrls.Should().ContainSingle()
            .Which.Should().Be("https://example.com/intermediate.cer");
    }

    [Fact]
    public async Task GetCrlAsync_CachesOnFirstCall_ReturnsCachedOnSecond()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/crl.crl", crlBytes);

        var crl1 = await cache.GetCrlAsync("https://example.com/crl.crl");
        crl1.Should().NotBeNull();
        handler.CallCount("https://example.com/crl.crl").Should().Be(1);

        var crl2 = await cache.GetCrlAsync("https://example.com/crl.crl");
        crl2.Should().NotBeNull();
        handler.CallCount("https://example.com/crl.crl").Should().Be(1, "second call should come from cache");

        cache.CachedCrlUrls.Should().ContainSingle()
            .Which.Should().Be("https://example.com/crl.crl");
    }

    [Fact]
    public async Task RemoveIntermediateAsync_RemovesSingleEntry()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();

        handler.SetResponse("https://example.com/a.cer", certBytes);
        handler.SetResponse("https://example.com/b.cer", certBytes);

        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        await cache.GetIntermediateCertificateAsync("https://example.com/b.cer");
        cache.CachedIntermediateUrls.Should().HaveCount(2);

        await cache.RemoveIntermediateAsync("https://example.com/a.cer");

        cache.CachedIntermediateUrls.Should().ContainSingle()
            .Which.Should().Be("https://example.com/b.cer");

        // Next fetch of removed URL should trigger a new download
        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        handler.CallCount("https://example.com/a.cer").Should().Be(2);
    }

    [Fact]
    public async Task RemoveCrlAsync_RemovesSingleEntry()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/a.crl", crlBytes);
        handler.SetResponse("https://example.com/b.crl", crlBytes);

        await cache.GetCrlAsync("https://example.com/a.crl");
        await cache.GetCrlAsync("https://example.com/b.crl");
        cache.CachedCrlUrls.Should().HaveCount(2);

        await cache.RemoveCrlAsync("https://example.com/a.crl");

        cache.CachedCrlUrls.Should().ContainSingle()
            .Which.Should().Be("https://example.com/b.crl");

        await cache.GetCrlAsync("https://example.com/a.crl");
        handler.CallCount("https://example.com/a.crl").Should().Be(2);
    }

    [Fact]
    public async Task RemoveAllIntermediatesAsync_RemovesAllIntermediateEntries()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/a.cer", certBytes);
        handler.SetResponse("https://example.com/b.cer", certBytes);
        handler.SetResponse("https://example.com/a.crl", crlBytes);

        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        await cache.GetIntermediateCertificateAsync("https://example.com/b.cer");
        await cache.GetCrlAsync("https://example.com/a.crl");

        await cache.RemoveAllIntermediatesAsync();

        cache.CachedIntermediateUrls.Should().BeEmpty();
        cache.CachedCrlUrls.Should().ContainSingle("CRLs should not be affected");
    }

    [Fact]
    public async Task RemoveAllCrlsAsync_RemovesAllCrlEntries()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/a.cer", certBytes);
        handler.SetResponse("https://example.com/a.crl", crlBytes);
        handler.SetResponse("https://example.com/b.crl", crlBytes);

        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        await cache.GetCrlAsync("https://example.com/a.crl");
        await cache.GetCrlAsync("https://example.com/b.crl");

        await cache.RemoveAllCrlsAsync();

        cache.CachedCrlUrls.Should().BeEmpty();
        cache.CachedIntermediateUrls.Should().ContainSingle("intermediates should not be affected");
    }

    [Fact]
    public async Task RemoveAllAsync_RemovesEverything()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://example.com/a.cer", certBytes);
        handler.SetResponse("https://example.com/a.crl", crlBytes);

        await cache.GetIntermediateCertificateAsync("https://example.com/a.cer");
        await cache.GetCrlAsync("https://example.com/a.crl");

        await cache.RemoveAllAsync();

        cache.CachedIntermediateUrls.Should().BeEmpty();
        cache.CachedCrlUrls.Should().BeEmpty();
    }

    [Fact]
    public async Task GetIntermediateCertificateAsync_DownloadFailure_ReturnsNull()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        handler.SetError("https://example.com/missing.cer", HttpStatusCode.NotFound);

        var result = await cache.GetIntermediateCertificateAsync("https://example.com/missing.cer");

        result.Should().BeNull();
        cache.CachedIntermediateUrls.Should().BeEmpty();
    }

    [Fact]
    public async Task GetCrlAsync_DownloadFailure_ReturnsNull()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        handler.SetError("https://example.com/missing.crl", HttpStatusCode.NotFound);

        var result = await cache.GetCrlAsync("https://example.com/missing.crl");

        result.Should().BeNull();
        cache.CachedCrlUrls.Should().BeEmpty();
    }

    [Fact]
    public void DI_Resolves_ICertificateDownloadCache()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        services.AddSingleton(new HttpClient());
        services.AddSingleton<ICertificateDownloadCache, CertificateDownloadCache>();

        var sp = services.BuildServiceProvider();
        var cache = sp.GetRequiredService<ICertificateDownloadCache>();

        cache.Should().NotBeNull();
        cache.Should().BeOfType<CertificateDownloadCache>();
    }

    [Fact]
    public void DI_Resolves_TrustChainValidator_With_Cache()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        services.AddSingleton(new HttpClient());
        services.AddSingleton<ICertificateDownloadCache, CertificateDownloadCache>();
        services.AddSingleton<TrustChainValidator>();

        var sp = services.BuildServiceProvider();
        var validator = sp.GetRequiredService<TrustChainValidator>();

        validator.Should().NotBeNull();
    }

    [Fact]
    public async Task MultipleCacheEntries_TracksSeparately()
    {
        var (cache, handler) = CreateCacheWithHandler(out _);
        var certBytes = CreateSelfSignedCertBytes();
        var crlBytes = CreateCrlBytes(hoursUntilNextUpdate: 24);

        handler.SetResponse("https://ca1.example.com/intermediate.cer", certBytes);
        handler.SetResponse("https://ca2.example.com/intermediate.cer", certBytes);
        handler.SetResponse("https://ca1.example.com/crl.crl", crlBytes);
        handler.SetResponse("https://ca2.example.com/crl.crl", crlBytes);

        await cache.GetIntermediateCertificateAsync("https://ca1.example.com/intermediate.cer");
        await cache.GetIntermediateCertificateAsync("https://ca2.example.com/intermediate.cer");
        await cache.GetCrlAsync("https://ca1.example.com/crl.crl");
        await cache.GetCrlAsync("https://ca2.example.com/crl.crl");

        cache.CachedIntermediateUrls.Should().HaveCount(2);
        cache.CachedCrlUrls.Should().HaveCount(2);

        // Remove one of each
        await cache.RemoveIntermediateAsync("https://ca1.example.com/intermediate.cer");
        await cache.RemoveCrlAsync("https://ca2.example.com/crl.crl");

        cache.CachedIntermediateUrls.Should().ContainSingle()
            .Which.Should().Be("https://ca2.example.com/intermediate.cer");
        cache.CachedCrlUrls.Should().ContainSingle()
            .Which.Should().Be("https://ca1.example.com/crl.crl");
    }

    #region Helpers

    private (CertificateDownloadCache cache, MockHttpHandler handler) CreateCacheWithHandler(
        out ServiceProvider sp)
    {
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);

        sp = services.BuildServiceProvider();
        var cacheProvider = sp.GetRequiredService<IFusionCacheProvider>();
        var logger = sp.GetRequiredService<ILogger<CertificateDownloadCache>>();

        var cache = new CertificateDownloadCache(cacheProvider, httpClient, logger);
        return (cache, handler);
    }

    private static byte[] CreateSelfSignedCertBytes()
    {
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGenerator.SetIssuerDN(new X509Name("CN=Test Intermediate CA"));
        certGenerator.SetSubjectDN(new X509Name("CN=Test Intermediate CA"));
        certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenerator.SetPublicKey(keyPair.Public);

        certGenerator.AddExtension(
            X509Extensions.BasicConstraints,
            true,
            new BasicConstraints(true));

        var signer = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        var bcCert = certGenerator.Generate(signer);

        return bcCert.GetEncoded();
    }

    private static byte[] CreateCrlBytes(int hoursUntilNextUpdate = 24)
    {
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(hoursUntilNextUpdate));

        var signer = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        var crl = crlGenerator.Generate(signer);

        return crl.GetEncoded();
    }

    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _responses = new();
        private readonly Dictionary<string, HttpStatusCode> _errors = new();
        private readonly Dictionary<string, int> _callCounts = new();

        public void SetResponse(string url, byte[] data)
        {
            _responses[url] = data;
        }

        public void SetError(string url, HttpStatusCode statusCode)
        {
            _errors[url] = statusCode;
        }

        public int CallCount(string url) =>
            _callCounts.TryGetValue(url, out var count) ? count : 0;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            _callCounts[url] = _callCounts.TryGetValue(url, out var count) ? count + 1 : 1;

            if (_errors.TryGetValue(url, out var statusCode))
            {
                return Task.FromResult(new HttpResponseMessage(statusCode));
            }

            if (_responses.TryGetValue(url, out var data))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(data)
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    #endregion
}

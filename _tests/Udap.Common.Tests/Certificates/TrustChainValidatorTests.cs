#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Metadata;
using Udap.Model;
using Udap.Util.Extensions;
using Xunit.Abstractions;
using ZiggyCreatures.Caching.Fusion;
using BcX509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Udap.Common.Tests.Certificates;
public class TrustChainValidatorTests
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IConfigurationRoot _configuration;
    private readonly FakeChainValidatorDiagnostics _diagnosticsChainValidator = new FakeChainValidatorDiagnostics();

    public TrustChainValidatorTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();
    }

    [Fact]
    public async Task GoodValidatorTest()
    {
        var file = _configuration["UdapMetadataOptionsFile"] ?? "udap.metadata.options.json";
        var json = File.ReadAllText(file);
        var udapMetadataOptions = JsonSerializer.Deserialize<UdapMetadataOptions>(json);
        var udapMetadataOptionsMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsMock.Value.Returns(udapMetadataOptions);
        
        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsMock, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4");

        // var metadata = disco.Json?.Deserialize<UdapMetadata>();
        var jwt = new JwtSecurityToken(metadata!.SignedMetadata);
        var tokenHeader = jwt.Header;
        // _testOutputHelper.WriteLine(tokenHeader.X5c);
        var x5CArray = JsonNode.Parse(tokenHeader.X5c)?.AsArray()!;
        
        var cert = new X509Certificate2(Convert.FromBase64String(x5CArray.First()!.ToString()));
        var tokenHandler = new JwtSecurityTokenHandler();
        
        tokenHandler.ValidateToken(metadata.SignedMetadata, new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuers = ["https://fhirlabs.net/fhir/r4"], //With ValidateIssuer = true issuer is validated against this list.  Docs are not clear on this, thus this example.
            ValidateAudience = false, // No aud for UDAP metadata
            ValidateLifetime = true,
            IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = [tokenHeader.Alg], //must match signing algorithm
        
        }, out _);

        //
        // Certificate revocation is offline for unit tests.
        //
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        Assert.True(await ValidateCertificateChain(cert, problemFlags, "udap://fhirlabs.net"));
        Assert.False(_diagnosticsChainValidator.Called);
    }

    [Fact]
    public async Task MissingCertificateForCommunityTest()
    {
        var udapMetadataOptions = new UdapMetadataOptions();
        _configuration.GetSection(Constants.UDAP_METADATA_OPTIONS).Bind(udapMetadataOptions);
        var udapMetadataOptionsProviderMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProviderMock.Value.Returns(udapMetadataOptions);

        _configuration.GetSection(Constants.UDAP_METADATA_OPTIONS).Bind(udapMetadataOptions);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProviderMock, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4", "http://MissingCertificate");

        Assert.Null(metadata);
    }

    [Fact]
    public async Task UnkownCommunityTest()
    {
        var udapMetadataOptionsProvider = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProvider.Value.Returns(new UdapMetadataOptions());
        _configuration.GetSection(Constants.UDAP_METADATA_OPTIONS).Bind(udapMetadataOptionsProvider);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProvider, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var metadata = await metaDataBuilder.SignMetaData("https://fhirlabs.net/fhir/r4", "udap://unknown");

        Assert.Null(metadata);
    }

    [Fact]
    public async Task FindCommunityTest()
    {
        var file = _configuration["UdapMetadataOptionsFile"] ?? "udap.metadata.options.json";
        var json = File.ReadAllText(file);
        var udapMetadataOptions = JsonSerializer.Deserialize<UdapMetadataOptions>(json);
        var udapMetadataOptionsProviderMock = Substitute.For<IUdapMetadataOptionsProvider>();
        udapMetadataOptionsProviderMock.Value.Returns(udapMetadataOptions);

        var udapFileCertStoreManifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(udapFileCertStoreManifest);

        var udapFileCertStoreManifestOptions = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        udapFileCertStoreManifestOptions.CurrentValue.Returns(udapFileCertStoreManifest);

        var privateCertificateStore = new IssuedCertificateStore(udapFileCertStoreManifestOptions, Substitute.For<ILogger<IssuedCertificateStore>>());
        var metaDataBuilder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            udapMetadataOptionsProviderMock, 
            privateCertificateStore, 
            Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());
        var communities = metaDataBuilder.GetCommunities();

        Assert.Equal(6, communities.Count);
        Assert.Contains(communities, c => c == "udap://fhirlabs.net");
        Assert.Contains(communities, c => c == "udap://expired.fhirlabs.net/");
        Assert.Contains(communities, c => c == "udap://untrusted.fhirlabs.net/");

        var communityHtml = await metaDataBuilder.GetCommunitiesAsHtml("https://baseurl");

        Assert.False(string.IsNullOrWhiteSpace(communityHtml));
        Assert.Contains("href=\"https://baseurl/.well-known/udap?community=udap://fhirlabs.net\"", communityHtml);
        Assert.Contains("href=\"https://baseurl/.well-known/udap?community=udap://untrusted.fhirlabs.net/\"", communityHtml);
    }

    [Fact]
    public async Task ValidateUntrustedCertificate()
    {
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();

        var services = new ServiceCollection();

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));

        var sp = services.BuildServiceProvider();
        var certStore = sp.GetRequiredService<ITrustAnchorStore>();

        var certificateStore = await certStore.Resolve();
        var anchors = certificateStore.AnchorCertificates.ToList();

        // Coverage for frameworks not hosted in example projects.  Funky but works.
        Assert.NotEmpty(certStore.AnchorCertificates.AsEnumerable().ToX509Collection());

        var intermediates = anchors
            .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
            .ToX509Collection();

        var anchorCertificates = anchors
            .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
            .OrderBy(certificate => certificate.NotBefore)
            .ToArray()
            .ToX509Collection();


        var validator = new TrustChainValidator(
            problemFlags,
            false, // no revocation checking in tests
            _testOutputHelper.ToLogger<TrustChainValidator>());

        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.Problems.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.untrusted.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);

        var trusted = await validator.IsTrustedCertificateAsync(
            "client_name",
            cert,
            intermediates,
            anchorCertificates!);

        Assert.False(trusted);
    }

    public async Task<bool> ValidateCertificateChain(
            X509Certificate2 issuedCertificate2,
            ChainProblemStatus problemFlags,
            string communityName)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
        .Build();

        var services = new ServiceCollection();

        // UDAP CertStore
        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));


        var sp = services.BuildServiceProvider();
        var certStore = sp.GetRequiredService<ITrustAnchorStore>();

        var certificateStore = await certStore.Resolve();
        var anchors = certificateStore.AnchorCertificates
            .Where(c => c.Community == communityName)
            .ToList();

        // Coverage for frameworks not hosted in example projects.  Funky but works.
        Assert.NotEmpty(certStore.AnchorCertificates.AsEnumerable().ToX509Collection());

        var intermediates = anchors
            .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
            .ToX509Collection();

        var anchorCertificates = anchors
            .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
            .OrderBy(certificate => certificate.NotBefore)
            .ToArray()
            .ToX509Collection();

        var validator = new TrustChainValidator(
            problemFlags,
            false, // no revocation checking in tests
            _testOutputHelper.ToLogger<TrustChainValidator>());

        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.Problems.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

        return await validator.IsTrustedCertificateAsync(
            "client_name",
            issuedCertificate2,
            intermediates,
            anchorCertificates!);
    }

    [Fact]
    public async Task RevokedCertificate_FiresProblemEvent_WithRevokedStatus()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/revoked-event-test.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with the leaf revoked
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        crlGenerator.AddCrlEntry(leafSerialNumber, DateTime.UtcNow.AddHours(-1), CrlReason.KeyCompromise);
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        var untrustedEvents = new List<X509Certificate2>();
        validator.Problem += element => problemEvents.Add(element);
        validator.Untrusted += cert => untrustedEvents.Add(cert);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);

        // Problem event should fire with Revoked status
        Assert.Single(problemEvents);
        var problem = problemEvents[0];
        Assert.Contains(problem.Problems, p => p.Status == ChainProblemStatus.Revoked);
        Assert.Contains(problem.Problems, p => p.StatusInformation.Contains("revoked"));

        // Untrusted event should fire for the leaf cert
        Assert.Single(untrustedEvents);
        Assert.Equal(leafDotNet.Thumbprint, untrustedEvents[0].Thumbprint);
    }

    [Fact]
    public async Task ExpiredCrl_FiresProblemEvent_WithRevocationStatusUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/expired-crl-test.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL that has already expired (NextUpdate in the past)
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddHours(-48));
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(-24)); // expired 24 hours ago
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        var untrustedEvents = new List<X509Certificate2>();
        validator.Problem += element => problemEvents.Add(element);
        validator.Untrusted += cert => untrustedEvents.Add(cert);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);

        // Problem event should fire with RevocationStatusUnknown
        Assert.Single(problemEvents);
        var problem = problemEvents[0];
        Assert.Contains(problem.Problems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);
        Assert.Contains(problem.Problems, p => p.StatusInformation.Contains("expired"));

        // Untrusted event should fire
        Assert.Single(untrustedEvents);
    }

    [Fact]
    public async Task ValidCertificate_NoEventsFiresWhenChainIsGood()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/valid-no-events-test.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with no revoked certs
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        var untrustedEvents = new List<X509Certificate2>();
        var errorEvents = new List<(X509Certificate2, Exception)>();
        validator.Problem += element => problemEvents.Add(element);
        validator.Untrusted += cert => untrustedEvents.Add(cert);
        validator.Error += (cert, ex) => errorEvents.Add((cert, ex));

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.True(result);
        Assert.Empty(problemEvents);
        Assert.Empty(untrustedEvents);
        Assert.Empty(errorEvents);
    }

    [Fact]
    public async Task NoCrlDistributionPoint_WithOfflineRevocationFlag_ReportsCrlNotFound()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        // Leaf cert WITHOUT a CRL distribution point
        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // CrlNotFound is not in DefaultProblemFlags (it's a soft-fail by default).
        // Include it explicitly to test that it causes chain failure.
        var problemFlags = TrustChainValidator.DefaultProblemFlags | ChainProblemStatus.CrlNotFound;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(problemEvents);
        Assert.Contains(problemEvents[0].Problems, p => p.Status == ChainProblemStatus.CrlNotFound);
        Assert.Contains(problemEvents[0].Problems, p => p.StatusInformation.Contains("CRL Distribution Point"));
    }

    [Fact]
    public async Task NoCrlDistributionPoint_WithoutOfflineRevocationFlag_NoProblemAdded()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // Exclude OfflineRevocation — no CrlNotFound problem should be added at all
        var problemFlags = ChainProblemStatus.NotTimeValid |
                           ChainProblemStatus.Revoked |
                           ChainProblemStatus.NotSignatureValid |
                           ChainProblemStatus.InvalidBasicConstraints;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        Assert.True(chainResult.IsValid);

        // No problems at all — CrlNotFound is not added when OfflineRevocation flag is absent
        var allProblems = chainResult.ChainElements.SelectMany(e => e.Problems).ToList();
        Assert.Empty(allProblems);
    }

    [Fact]
    public async Task NoCrlDistributionPoint_DefaultFlags_SoftFail()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        var bcLeafCert = CreateLeafCertWithoutCrlDp(caKeyPair, bcRootCert, leafSerialNumber);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // DefaultProblemFlags includes OfflineRevocation, so CrlNotFound IS added,
        // but CrlNotFound itself is not in DefaultProblemFlags, so chain passes (soft-fail).
        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // Chain is valid (CrlNotFound is soft-fail)
        Assert.True(chainResult.IsValid);

        // But the CrlNotFound problem IS recorded in chain elements
        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.CrlNotFound);
    }

    [Fact]
    public async Task CrlDownloadFails_DefaultFlags_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/missing.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // MockHttpHandler with no response registered for the CRL URL → returns 404
        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // No CRL was successfully checked → RevocationStatusUnknown (in DefaultProblemFlags) → chain invalid
        Assert.False(chainResult.IsValid);

        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);

        Assert.Single(problemEvents);
    }

    [Fact]
    public async Task CrlDownloadFails_WithCrlFetchFailedFlag_FailsValidation()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/missing-hard-fail.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var handler = new MockHttpHandler();
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // Include CrlFetchFailed in flags to make it a hard failure
        var problemFlags = TrustChainValidator.DefaultProblemFlags | ChainProblemStatus.CrlFetchFailed;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(problemEvents);
        Assert.Contains(problemEvents[0].Problems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
    }

    [Fact]
    public async Task CrlSignedByWrongIssuer_DefaultFlags_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/wrong-issuer.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL signed by a DIFFERENT key (not the CA)
        var rogueKeyPairGenerator = new RsaKeyPairGenerator();
        rogueKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var rogueKeyPair = rogueKeyPairGenerator.GenerateKeyPair();

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", rogueKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // CRL signature failed → no CRL successfully checked → RevocationStatusUnknown → chain invalid
        Assert.False(chainResult.IsValid);

        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);
    }

    [Fact]
    public async Task NoHttpClientOrCache_DefaultFlags_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/no-client.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // No cache, no HttpClient
        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: null);

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // No CRL checked → RevocationStatusUnknown → chain invalid
        Assert.False(chainResult.IsValid);

        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
        Assert.Contains(leafProblems, p => p.Status == ChainProblemStatus.RevocationStatusUnknown);

        Assert.Single(problemEvents);
    }

    [Fact]
    public async Task RelativeDistributionPointName_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/after-relative.crl";

        // Create leaf with two CDPs: first is NameRelativeToCRLIssuer (skipped), second is valid URI
        var bcLeafCert = CreateLeafCertWithMultipleCdps(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Relative DP was skipped, valid URI DP was used, cert is not revoked
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task NonUriGeneralName_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/after-non-uri.crl";

        // Create leaf with a CDP containing a non-URI general name followed by a valid URI
        var bcLeafCert = CreateLeafCertWithNonUriGeneralName(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Non-URI general name was skipped, valid URI was used
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task EmptyUriInCdp_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/after-empty-uri.crl";

        // Create leaf with a CDP containing an empty URI followed by a valid URI
        var bcLeafCert = CreateLeafCertWithEmptyUri(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // Empty URI was skipped, valid URI was used
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(crlUrl));
    }

    [Fact]
    public async Task CrlWithNoNextUpdate_IsNotTreatedAsExpired()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/no-next-update.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with NO NextUpdate field
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        // Deliberately not calling SetNextUpdate
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // CRL with no NextUpdate should not be treated as expired
        Assert.True(result);
    }

    [Fact]
    public async Task CrlVerification_SkippedWhenCertIsLastInChain()
    {
        // When certIndex + 1 >= chain.Count, the CRL signature verification
        // is skipped (no issuer available to verify against). This happens when
        // a self-signed cert with a CDP is validated as the only cert in the chain.

        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var serialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/self-signed.crl";

        // Self-signed cert that is ALSO a trust anchor, with a CDP
        var certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetIssuerDN(new X509Name("CN=Self Signed"));
        certGenerator.SetSubjectDN(new X509Name("CN=Self Signed"));
        certGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenerator.SetPublicKey(keyPair.Public);
        certGenerator.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        certGenerator.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            new SubjectKeyIdentifierStructure(keyPair.Public));

        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        certGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));

        var bcCert = certGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private));

        // CRL signed by the same key (valid for self-signed), cert not revoked
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Self Signed"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var dotNetCert = new X509Certificate2(bcCert.GetEncoded());
        // Use the same cert as both the leaf and the anchor
        var anchors = new X509Certificate2Collection(dotNetCert);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            dotNetCert,
            intermediateCertificates: null,
            anchors);

        Assert.True(result);
    }

    [Fact]
    public async Task MalformedCdpExtension_CatchesException_ReportsCrlFetchFailed()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());

        // Create a leaf cert with a malformed CRL Distribution Points extension
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(leafSerialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf Malformed CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));
        // Add a malformed CDP extension (raw garbage bytes wrapped in OCTET STRING)
        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new Org.BouncyCastle.Asn1.DerUtf8String("not-a-valid-cdp"));

        var bcLeafCert = leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        // Use CrlFetchFailed in flags so the outer catch causes failure
        var problemFlags = TrustChainValidator.DefaultProblemFlags | ChainProblemStatus.CrlFetchFailed;

        var validator = new TrustChainValidator(
            problemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: new HttpClient());

        var problemEvents = new List<ChainElementInfo>();
        validator.Problem += element => problemEvents.Add(element);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);
        Assert.Single(problemEvents);
        Assert.Contains(problemEvents[0].Problems, p => p.Status == ChainProblemStatus.CrlFetchFailed);
        Assert.Contains(problemEvents[0].Problems, p => p.StatusInformation.Contains("Error checking CRL"));
    }

    [Fact]
    public async Task CrlWithThisUpdateInFuture_RevocationUnknown()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/future-this-update.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // CRL with ThisUpdate in the future (clock skew or bad CRL)
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddHours(24)); // future!
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(48));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var chainResult = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            null,
            anchors,
            null);

        // ThisUpdate in the future → RevocationStatusUnknown → chain invalid
        Assert.False(chainResult.IsValid);
        var leafProblems = chainResult.ChainElements[0].Problems;
        Assert.Contains(leafProblems, p =>
            p.Status == ChainProblemStatus.RevocationStatusUnknown &&
            p.StatusInformation.Contains("ThisUpdate in the future"));
    }

    [Fact]
    public async Task CrlDpWithNonHttpScheme_IsSkipped_FallsThrough()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string validCrlUrl = "https://example.com/valid.crl";

        // Create leaf with two CDPs: first is ldap:// (skipped), second is https://
        var bcLeafCert = CreateLeafCertWithUnsupportedScheme(caKeyPair, bcRootCert, leafSerialNumber, validCrlUrl);

        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow);
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var handler = new MockHttpHandler();
        handler.SetResponse(validCrlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(handler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        var sp = services.BuildServiceProvider();
        var logger = sp.GetRequiredService<ILogger<TrustChainValidator>>();

        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            logger,
            downloadCache: null,
            httpClient: httpClient);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        // ldap:// URI was skipped, https:// was used, cert is not revoked
        Assert.True(result);
        Assert.Equal(1, handler.CallCount(validCrlUrl));
    }

    [Fact]
    public async Task ExpiredCrl_WithCache_EvictsStaleEntry()
    {
        var (caKeyPair, bcRootCert) = CreateCaKeyPairAndRoot();
        var leafSerialNumber = BigInteger.ProbablePrime(120, new Random());
        const string crlUrl = "https://example.com/expired-cached.crl";

        var bcLeafCert = CreateLeafCert(caKeyPair, bcRootCert, leafSerialNumber, crlUrl);

        // Expired CRL
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddHours(-48));
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(-24));
        var crl = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));

        var mockHandler = new MockHttpHandler();
        mockHandler.SetResponse(crlUrl, crl.GetEncoded());
        var httpClient = new HttpClient(mockHandler);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddXUnit(_testOutputHelper));
        services.AddFusionCache(CertificateDownloadCache.CacheName);
        var sp = services.BuildServiceProvider();

        var cacheProvider = sp.GetRequiredService<IFusionCacheProvider>();
        var cacheLogger = sp.GetRequiredService<ILogger<CertificateDownloadCache>>();
        var downloadCache = new CertificateDownloadCache(cacheProvider, httpClient, cacheLogger);

        var validatorLogger = sp.GetRequiredService<ILogger<TrustChainValidator>>();
        var validator = new TrustChainValidator(
            TrustChainValidator.DefaultProblemFlags,
            true,
            validatorLogger,
            downloadCache: downloadCache);

        var leafDotNet = new X509Certificate2(bcLeafCert.GetEncoded());
        var rootDotNet = new X509Certificate2(bcRootCert.GetEncoded());
        var anchors = new X509Certificate2Collection(rootDotNet);

        // First call: downloads and caches the expired CRL, then evicts it
        var result = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result);

        // Second call should re-download because the stale entry was evicted
        var result2 = await validator.IsTrustedCertificateAsync(
            "test_client",
            leafDotNet,
            intermediateCertificates: null,
            anchors);

        Assert.False(result2);
        // The CRL was downloaded twice (evicted after first call)
        Assert.Equal(2, mockHandler.CallCount(crlUrl));
    }

    #region Test Helpers

    private static (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair, Org.BouncyCastle.X509.X509Certificate bcRootCert) CreateCaKeyPairAndRoot()
    {
        var caKeyPairGenerator = new RsaKeyPairGenerator();
        caKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var caKeyPair = caKeyPairGenerator.GenerateKeyPair();

        var caCertGenerator = new X509V3CertificateGenerator();
        caCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        caCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetSubjectDN(new X509Name("CN=Test Root CA"));
        caCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        caCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        caCertGenerator.SetPublicKey(caKeyPair.Public);
        caCertGenerator.AddExtension(BcX509Extensions.BasicConstraints, true, new BasicConstraints(true));
        caCertGenerator.AddExtension(BcX509Extensions.SubjectKeyIdentifier, false,
            new SubjectKeyIdentifierStructure(caKeyPair.Public));

        var bcRootCert = caCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
        return (caKeyPair, bcRootCert);
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCert(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string crlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        var crlDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
            null, null);
        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { crlDp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithMultipleCdps(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf Multi CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // First DP: NameRelativeToCRLIssuer (not FullName → line 589 continue)
        var relativeDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.NameRelativeToCrlIssuer,
                new X509Name("CN=CRL Issuer")),
            null, null);

        // Second DP: valid FullName URI
        var validDp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl))),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { relativeDp, validDp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithNonUriGeneralName(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf NonURI"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // Single DP with two general names: first is DirectoryName (not URI → line 597 continue),
        // second is a valid URI
        var dp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new[]
                {
                    new GeneralName(GeneralName.DirectoryName, new X509Name("CN=Not A URI")),
                    new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl)
                })),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { dp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithEmptyUri(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf EmptyURI"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // Single DP with two URI general names: first is empty (line 603 continue), second is valid
        var dp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new[]
                {
                    new GeneralName(GeneralName.UniformResourceIdentifier, ""),
                    new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl)
                })),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { dp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithUnsupportedScheme(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber,
        string validCrlUrl)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf LDAP CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);

        // Single DP with two URIs: first is ldap:// (unsupported scheme), second is valid https://
        var dp = new DistributionPoint(
            new DistributionPointName(
                DistributionPointName.FullName,
                new GeneralNames(new[]
                {
                    new GeneralName(GeneralName.UniformResourceIdentifier, "ldap://example.com/cn=CRL"),
                    new GeneralName(GeneralName.UniformResourceIdentifier, validCrlUrl)
                })),
            null, null);

        leafCertGenerator.AddExtension(BcX509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { dp }));
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private static Org.BouncyCastle.X509.X509Certificate CreateLeafCertWithoutCrlDp(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair caKeyPair,
        Org.BouncyCastle.X509.X509Certificate bcRootCert,
        BigInteger serialNumber)
    {
        var leafKeyPairGenerator = new RsaKeyPairGenerator();
        leafKeyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var leafKeyPair = leafKeyPairGenerator.GenerateKeyPair();

        var leafCertGenerator = new X509V3CertificateGenerator();
        leafCertGenerator.SetSerialNumber(serialNumber);
        leafCertGenerator.SetIssuerDN(new X509Name("CN=Test Root CA"));
        leafCertGenerator.SetSubjectDN(new X509Name("CN=Test Leaf No CDP"));
        leafCertGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        leafCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        leafCertGenerator.SetPublicKey(leafKeyPair.Public);
        leafCertGenerator.AddExtension(BcX509Extensions.AuthorityKeyIdentifier, false,
            new AuthorityKeyIdentifierStructure(bcRootCert));

        return leafCertGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caKeyPair.Private));
    }

    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _responses = new();
        private readonly Dictionary<string, int> _callCounts = new();

        public void SetResponse(string url, byte[] data) => _responses[url] = data;

        public int CallCount(string url) =>
            _callCounts.TryGetValue(url, out var count) ? count : 0;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            _callCounts[url] = _callCounts.TryGetValue(url, out var count) ? count + 1 : 1;

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

    public class FakeChainValidatorDiagnostics
    {
        public bool Called;

        private readonly List<string> _actualErrorMessages = new List<string>();
        public List<string> ActualErrorMessages
        {
            get { return _actualErrorMessages; }
        }

        public void OnChainProblem(ChainElementInfo chainElement)
        {
            foreach (var problem in chainElement.Problems
                         .Where(p => (p.Status & TrustChainValidator.DefaultProblemFlags) != 0))
            {
                var msg = $"Trust ERROR ({problem.Status}){problem.StatusInformation}, {chainElement.Certificate}";
                _actualErrorMessages.Add(msg);
                Called = true;
            }
        }
    }

}

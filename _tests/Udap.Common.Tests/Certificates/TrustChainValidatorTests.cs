#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Metadata;
using Udap.Model;
using Udap.Util.Extensions;
using Xunit.Abstractions;

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
        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;
        
        (await ValidateCertificateChain(cert, problemFlags, "udap://fhirlabs.net")).Should().BeTrue();
        _diagnosticsChainValidator.Called.Should().BeFalse();
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

        metadata.Should().BeNull();
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

        metadata.Should().BeNull();
    }

    [Fact]
    public Task FindCommunityTest()
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

        communities.Count.Should().Be(6);
        communities.Should().Contain(c => c == "udap://fhirlabs.net");
        communities.Should().Contain(c => c == "udap://expired.fhirlabs.net/");
        communities.Should().Contain(c => c == "udap://untrusted.fhirlabs.net/");

        var communityHtml = metaDataBuilder.GetCommunitiesAsHtml("https://baseurl");

        communityHtml.Should().NotBeNullOrWhiteSpace();
        communityHtml.Should().Contain("href=\"https://baseurl/.well-known/udap?community=udap://fhirlabs.net\"");
        communityHtml.Should().Contain("href=\"https://baseurl/.well-known/udap?community=udap://untrusted.fhirlabs.net/\"");
        return Task.CompletedTask;
    }

    [Fact]
    public async Task ValidateUntrustedCertificate()
    {
        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           // X509ChainStatusFlags.OfflineRevocation |
                           X509ChainStatusFlags.CtlNotSignatureValid;

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
        certStore.AnchorCertificates.AsEnumerable().ToX509Collection().Should().NotBeNullOrEmpty();

        var intermediates = anchors
            .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
            .ToX509Collection();

        var anchorCertificates = anchors
            .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
            .OrderBy(certificate => certificate.NotBefore)
            .ToArray()
            .ToX509Collection();


        var validator = new TrustChainValidator(new X509ChainPolicy()
        {
            RevocationMode = X509RevocationMode.Offline,
            VerificationFlags = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                X509VerificationFlags.IgnoreEndRevocationUnknown |
                                X509VerificationFlags.AllowUnknownCertificateAuthority |
                                X509VerificationFlags.IgnoreWrongUsage,
            RevocationFlag = X509RevocationFlag.ExcludeRoot
        }, problemFlags, _testOutputHelper.ToLogger<TrustChainValidator>());

        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.ChainElementStatus.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

        var cert = new X509Certificate2("CertStore/issued/fhirlabs.net.untrusted.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
        
        var trusted = validator.IsTrustedCertificate(
            "client_name",
            cert,
            intermediates,
            anchorCertificates!,
            out _,
            out _);

        trusted.Should().BeFalse();
    }

    public async Task<bool> ValidateCertificateChain(
            X509Certificate2 issuedCertificate2,
            X509ChainStatusFlags problemFlags,
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
        certStore.AnchorCertificates.AsEnumerable().ToX509Collection().Should().NotBeNullOrEmpty();

        var intermediates = anchors
            .SelectMany(a => a.Intermediates!.Select(i => X509Certificate2.CreateFromPem(i.Certificate))).ToArray()
            .ToX509Collection();

        var anchorCertificates = anchors
            .Select(c => X509Certificate2.CreateFromPem(c.Certificate))
            .OrderBy(certificate => certificate.NotBefore)
            .ToArray()
            .ToX509Collection();

        var validator = new TrustChainValidator(new X509ChainPolicy()
        {
            RevocationMode = X509RevocationMode.Offline,
            VerificationFlags = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                                  X509VerificationFlags.IgnoreEndRevocationUnknown |
                                                  X509VerificationFlags.AllowUnknownCertificateAuthority |
                                                  X509VerificationFlags.IgnoreWrongUsage,
            RevocationFlag = X509RevocationFlag.ExcludeRoot
        }, problemFlags, _testOutputHelper.ToLogger<TrustChainValidator>());

        validator.Problem += _diagnosticsChainValidator.OnChainProblem;

        // Help while writing tests to see problems summarized.
        validator.Error += (_, exception) => _testOutputHelper.WriteLine("Error: " + exception.Message);
        validator.Problem += element => _testOutputHelper.WriteLine("Problem: " + element.ChainElementStatus.Summarize(problemFlags));
        validator.Untrusted += certificate2 => _testOutputHelper.WriteLine("Untrusted: " + certificate2.Subject);

        return validator.IsTrustedCertificate(
            "client_name",
            issuedCertificate2,
            intermediates,
            anchorCertificates!,
            out _,
            out _);
    }

    public class FakeChainValidatorDiagnostics
    {
        public bool Called;

        private readonly List<string> _actualErrorMessages = new List<string>();
        public List<string> ActualErrorMessages
        {
            get { return _actualErrorMessages; }
        }

        public void OnChainProblem(X509ChainElement chainElement)
        {
            foreach (var chainElementStatus in chainElement.ChainElementStatus
                         .Where(s => (s.Status & TrustChainValidator.DefaultProblemFlags) != 0))
            {
                var problem = $"Trust ERROR ({chainElementStatus.Status}){chainElementStatus.StatusInformation}, {chainElement.Certificate}";
                _actualErrorMessages.Add(problem);
                Called = true;
            }
        }
    }

}

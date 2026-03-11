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
using FluentAssertions;
using Duende.IdentityModel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Support.Tests.Client;
using Xunit.Abstractions;

namespace UdapMetadata.Tests.FhirLabsApi;

public class UdapControllerMultiHostTest : IClassFixture<ApiForCommunityTestFixture>
{
    private readonly ApiForCommunityTestFixture _fixture;
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly IServiceProvider _serviceProvider;
    private readonly FakeValidatorDiagnostics _diagnosticsValidator = new FakeValidatorDiagnostics();

    private static readonly string[] DomainSegments =
        { "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten" };

    public UdapControllerMultiHostTest(ApiForCommunityTestFixture fixture, ITestOutputHelper testOutputHelper)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        fixture.Output = testOutputHelper;
        _fixture = fixture;
        _testOutputHelper = testOutputHelper;

        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.FhirLabsApi.json", false, true)
            .Build();

        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(testOutputHelper);
        });

        services.Configure<UdapFileCertStoreManifest>(configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST));
        services.AddSingleton<ITrustAnchorStore>(sp =>
            new TrustAnchorFileStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                Substitute.For<ILogger<TrustAnchorFileStore>>()));

        var problemFlags = X509ChainStatusFlags.NotTimeValid |
                           X509ChainStatusFlags.Revoked |
                           X509ChainStatusFlags.NotSignatureValid |
                           X509ChainStatusFlags.InvalidBasicConstraints |
                           X509ChainStatusFlags.CtlNotTimeValid |
                           X509ChainStatusFlags.UntrustedRoot |
                           X509ChainStatusFlags.CtlNotSignatureValid;

        services.TryAddScoped(_ =>
            new TrustChainValidator(
                new X509ChainPolicy()
                {
                    DisableCertificateDownloads = true,
                    UrlRetrievalTimeout = TimeSpan.FromMilliseconds(1),
                    RevocationMode = X509RevocationMode.NoCheck
                },
                problemFlags,
                _testOutputHelper.ToLogger<TrustChainValidator>()));

        services.AddSingleton<UdapClientDiscoveryValidator>();

        services.AddScoped<IUdapClient>(sp =>
            new UdapClient(_fixture.CreateClient(),
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task ValidateAllMultiHostDomainsTest()
    {
        var udapClient = _serviceProvider.GetRequiredService<IUdapClient>();
        udapClient.Problem += _diagnosticsValidator.OnChainProblem;
        udapClient.Untrusted += _diagnosticsValidator.OnUnTrusted;
        udapClient.TokenError += _diagnosticsValidator.OnTokenError;

        var signedMetadataResults = new HashSet<string>();

        foreach (var segment in DomainSegments)
        {
            var baseUrl = $"https://localhost:7016/{segment}/fhir/r4";

            var disco = await udapClient.ValidateResource(baseUrl, "udap://multihost/");

            disco.IsError.Should().BeFalse(
                $"Segment '{segment}': {disco.Error} | {disco.ErrorType} | {string.Join("; ", _diagnosticsValidator.ActualErrorMessages)}");
            udapClient.UdapServerMetaData.Should().NotBeNull();
            _diagnosticsValidator.ProblemCalled.Should().BeFalse(
                $"Segment '{segment}': chain problem: {string.Join("; ", _diagnosticsValidator.ActualErrorMessages)}");
            _diagnosticsValidator.UntrustedCalled.Should().BeFalse(
                $"Segment '{segment}': untrusted: {_diagnosticsValidator.UnTrustedCertificate}");
            _diagnosticsValidator.TokenErrorCalled.Should().BeFalse(
                $"Segment '{segment}': token error: {string.Join("; ", _diagnosticsValidator.ActualErrorMessages)}");

            // Verify issuer matches the requested base URL
            var jwt = new JwtSecurityToken(disco.SignedMetadata);
            var issClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Issuer);
            issClaim.Value.Should().Be(baseUrl,
                $"Segment '{segment}': iss should match the requested base URL");

            // Verify subject matches issuer
            var subClaim = jwt.Payload.Claims.Single(c => c.Type == JwtClaimTypes.Subject);
            subClaim.Value.Should().Be(issClaim.Value);

            // Verify signing cert SAN matches the base URL
            var x5cArray = jwt.Header["x5c"] as List<object>;
            var cert = new X509Certificate2(Convert.FromBase64String(x5cArray!.First().ToString()!));
            var subjectAltName = cert.GetNameInfo(X509NameType.UrlName, false);
            subjectAltName.Should().Be(baseUrl,
                $"Segment '{segment}': cert SAN should match the requested base URL");

            // Collect signed_metadata to verify they're all different
            signedMetadataResults.Add(disco.SignedMetadata!);

            _testOutputHelper.WriteLine($"Validated: {baseUrl} -> iss={issClaim.Value}, SAN={subjectAltName}");
        }

        // All 10 should have different signed metadata (different certs, different signatures)
        signedMetadataResults.Count.Should().Be(DomainSegments.Length,
            "Each domain should produce different signed metadata");
    }

    [Fact]
    public async Task UnknownDomainReturns404Test()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync(
            "https://localhost:7016/eleven/fhir/r4/.well-known/udap?community=udap://multihost/");

        response.StatusCode.Should().Be(System.Net.HttpStatusCode.NotFound);
    }
}

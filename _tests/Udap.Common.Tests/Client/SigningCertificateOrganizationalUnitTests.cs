#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Model;
using Udap.Tefca.Model;

namespace Udap.Common.Tests.Client;

/// <summary>
/// Optional subject OU policy binding for the server's metadata signing certificate
/// (<see cref="DiscoveryPolicy.RequiredSigningCertificateOrganizationalUnits"/>).
/// Certificates are built in-test because the generated test PKI does not carry the TEFCA OUs.
/// </summary>
public class SigningCertificateOrganizationalUnitTests
{
    private const string BaseUrl = "https://fhirlabs.net/fhir/r4";

    [Fact]
    public void DiscoveryPolicy_DefaultHasNoOuPolicy()
    {
        Assert.Empty(new DiscoveryPolicy().RequiredSigningCertificateOrganizationalUnits);
        Assert.Empty(DiscoveryPolicy.DefaultMetadataServerPolicy().RequiredSigningCertificateOrganizationalUnits);
    }

    [Theory]
    [InlineData("CN=fhirlabs, OU=RCE-FHIR, O=FhirLabs", TefcaConstants.OrganizationalUnits.Production, true)]
    [InlineData("CN=fhirlabs, OU=Direct, OU=RCE-FHIR, O=FhirLabs", TefcaConstants.OrganizationalUnits.Production, true)]
    [InlineData("CN=fhirlabs, OU=RCE-FHIR-TEST, O=FhirLabs", TefcaConstants.OrganizationalUnits.Validation, true)]
    [InlineData("CN=fhirlabs, O=FhirLabs", TefcaConstants.OrganizationalUnits.Production, false)]
    [InlineData("CN=fhirlabs, OU=RCE-FHIR, O=FhirLabs", TefcaConstants.OrganizationalUnits.Validation, false)]
    [InlineData("CN=fhirlabs, OU=RCE-FHIR-TEST, O=FhirLabs", TefcaConstants.OrganizationalUnits.Production, false)]
    public async Task ValidateSigningCertificateOrganizationalUnit(string subject, string requiredOu, bool expected)
    {
        using var cert = CreateCertificate(subject);
        var validator = CreateValidator();
        string? tokenError = null;
        validator.TokenError += message => tokenError = message;

        var jwtValid = await validator.ValidateJwtToken(CreateMetadata(cert), BaseUrl);
        Assert.True(jwtValid, tokenError);

        var result = validator.ValidateSigningCertificateOrganizationalUnit([requiredOu]);

        Assert.Equal(expected, result);
        if (!expected)
        {
            Assert.NotNull(tokenError);
            Assert.Contains(requiredOu, tokenError);
        }
    }

    [Fact]
    public async Task ValidateSigningCertificateOrganizationalUnit_NoPolicy_Passes()
    {
        using var cert = CreateCertificate("CN=fhirlabs, O=FhirLabs");
        var validator = CreateValidator();

        Assert.True(await validator.ValidateJwtToken(CreateMetadata(cert), BaseUrl));
        Assert.True(validator.ValidateSigningCertificateOrganizationalUnit(null));
        Assert.True(validator.ValidateSigningCertificateOrganizationalUnit([]));
    }

    [Fact]
    public void ValidateSigningCertificateOrganizationalUnit_NoCertificateRead_Fails()
    {
        var validator = CreateValidator();

        Assert.False(validator.ValidateSigningCertificateOrganizationalUnit([TefcaConstants.OrganizationalUnits.Production]));
    }

    [Theory]
    [InlineData("CN=fhirlabs, OU=RCE-FHIR, O=FhirLabs", false)]
    [InlineData("CN=fhirlabs, O=FhirLabs", true)]
    [InlineData("CN=fhirlabs, OU=RCE-FHIR-TEST, O=FhirLabs", true)]
    public async Task ValidateResource_EnforcesPolicyOu(string subject, bool expectError)
    {
        using var cert = CreateCertificate(subject);
        var udapClient = CreateClient(() => cert);

        var disco = await udapClient.ValidateResource(BaseUrl, TefcaConstants.CommunityUri, TefcaPolicy());

        Assert.Equal(expectError, disco.IsError);
        if (expectError)
        {
            Assert.Contains("Organizational Unit", disco.Error);
        }
    }

    [Fact]
    public async Task ValidateResource_SameClientAndPolicy_OuEnforcedOnlyForMappedCommunity()
    {
        using var tefcaCertWithoutOu = CreateCertificate("CN=tefca, O=FhirLabs");
        using var otherCommunityCert = CreateCertificate("CN=other, O=FhirLabs");
        var current = tefcaCertWithoutOu;
        var udapClient = CreateClient(() => current);
        var policy = TefcaPolicy();

        // TEFCA discovery: the certificate lacks RCE-FHIR, so discovery fails.
        var tefcaDisco = await udapClient.ValidateResource(BaseUrl, TefcaConstants.CommunityUri, policy);
        Assert.True(tefcaDisco.IsError);
        Assert.Contains("Organizational Unit", tefcaDisco.Error);

        // Same client, same policy, a different community: no OU requirement carries over.
        current = otherCommunityCert;
        var otherDisco = await udapClient.ValidateResource(BaseUrl, "udap://fhirlabs.net", policy);
        Assert.False(otherDisco.IsError, otherDisco.Error);

        // No community argument: no OU check either.
        var noCommunityDisco = await udapClient.ValidateResource(BaseUrl, (string?)null, policy);
        Assert.False(noCommunityDisco.IsError, noCommunityDisco.Error);

        // The policy is kept by the client; a later TEFCA discovery is still enforced.
        current = tefcaCertWithoutOu;
        var tefcaAgain = await udapClient.ValidateResource(BaseUrl, TefcaConstants.CommunityUri, (DiscoveryPolicy?)null);
        Assert.True(tefcaAgain.IsError);
    }

    [Fact]
    public void GetRequiredSigningCertificateOrganizationalUnits_ResolvesByCommunity()
    {
        var policy = TefcaPolicy();
        policy.RequiredSigningCertificateOrganizationalUnits["udap://empty"] = new List<string>();

        Assert.Contains(
            TefcaConstants.OrganizationalUnits.Production,
            policy.GetRequiredSigningCertificateOrganizationalUnits(TefcaConstants.CommunityUri)!);
        Assert.Null(policy.GetRequiredSigningCertificateOrganizationalUnits("udap://fhirlabs.net"));
        Assert.Null(policy.GetRequiredSigningCertificateOrganizationalUnits("udap://empty"));
        Assert.Null(policy.GetRequiredSigningCertificateOrganizationalUnits(null));
    }

    private static DiscoveryPolicy TefcaPolicy()
    {
        var policy = DiscoveryPolicy.DefaultMetadataServerPolicy();
        policy.RequiredSigningCertificateOrganizationalUnits[TefcaConstants.CommunityUri] =
            new List<string> { TefcaConstants.OrganizationalUnits.Production };

        return policy;
    }

    /// <summary>
    /// A UdapClient whose discovery responses are signed by whatever certificate
    /// <paramref name="currentCertificate"/> returns at request time.
    /// </summary>
    private static UdapClient CreateClient(Func<X509Certificate2> currentCertificate)
    {
        var httpClient = Substitute.For<HttpClient>();
        httpClient.SendAsync(Arg.Any<HttpRequestMessage>(), Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                var metadata = CreateMetadata(currentCertificate());
                var metadataJson = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    [UdapConstants.Discovery.UdapVersionsSupported] = metadata.UdapVersionsSupported,
                    [UdapConstants.Discovery.TokenEndpoint] = metadata.TokenEndpoint,
                    [UdapConstants.Discovery.RegistrationEndpoint] = metadata.RegistrationEndpoint,
                    [UdapConstants.Discovery.SignedMetadata] = metadata.SignedMetadata
                });

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadataJson)
                });
            });

        // The trust chain itself is out of scope here: the in-test certificates are self-signed.
        var validator = Substitute.ForPartsOf<UdapClientDiscoveryValidator>(
            new TrustChainValidator(new ChainProblemStatus(), false, NullLogger<TrustChainValidator>.Instance),
            NullLogger<UdapClientDiscoveryValidator>.Instance,
            null);
        validator.ValidateTrustChain(Arg.Any<string?>(), Arg.Any<ITrustAnchorStore?>()).Returns(true);

        var options = Substitute.For<IOptionsMonitor<UdapClientOptions>>();
        options.CurrentValue.Returns(new UdapClientOptions());

        return new UdapClient(httpClient, validator, options, NullLogger<UdapClient>.Instance);
    }

    private static UdapClientDiscoveryValidator CreateValidator()
    {
        return new UdapClientDiscoveryValidator(
            new TrustChainValidator(new ChainProblemStatus(), false, NullLogger<TrustChainValidator>.Instance),
            NullLogger<UdapClientDiscoveryValidator>.Instance);
    }

    private static X509Certificate2 CreateCertificate(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri(BaseUrl));
        request.CertificateExtensions.Add(san.Build());

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static UdapMetadata CreateMetadata(X509Certificate2 cert)
    {
        var tokenEndpoint = "https://fhirlabs.net/connect/token";
        var registrationEndpoint = "https://fhirlabs.net/connect/register";

        var handler = new JsonWebTokenHandler();
        var signedMetadata = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = BaseUrl,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = BaseUrl,
                [UdapConstants.Discovery.TokenEndpoint] = tokenEndpoint,
                [UdapConstants.Discovery.RegistrationEndpoint] = registrationEndpoint
            },
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(
                new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["x5c"] = new[] { Convert.ToBase64String(cert.RawData) }
            }
        });

        return new UdapMetadata
        {
            UdapVersionsSupported = ["1"],
            TokenEndpoint = tokenEndpoint,
            RegistrationEndpoint = registrationEndpoint,
            SignedMetadata = signedMetadata
        };
    }
}

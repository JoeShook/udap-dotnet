#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Common.Certificates;
using Udap.Common.Metadata;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;

namespace Udap.Common.Tests.Client;

/// <summary>
/// HL7 SSRAA 3.0.0 general requirements, "Normalization of URI values in JWTs": the signed metadata
/// <c>iss</c> is compared with the FHIR base URL and the certificate URI SAN as exact, case-sensitive strings
/// under <see cref="SsraaVersion.V2_0"/> and <see cref="SsraaVersion.V3_0"/>, and a FHIR base URL must not end
/// in "/" under <see cref="SsraaVersion.V3_0"/>. <see cref="SsraaVersion.V1_1"/> keeps the lenient comparison.
/// </summary>
public class SsraaUriComparisonTests
{
    private const string BaseUrl = "https://a.example.com/fhir";

    [Fact]
    public void Defaults_Are_V3_0()
    {
        Assert.Equal(SsraaVersion.V3_0, CreateValidator(null).SsraaVersion);
        Assert.Null(new DiscoveryPolicy().SsraaVersion);
        Assert.Equal(SsraaVersion.V3_0, new UdapMetadataOptions().SsraaVersion);
    }

    [Theory]
    [InlineData(SsraaVersion.V1_1)]
    [InlineData(SsraaVersion.V2_0)]
    [InlineData(SsraaVersion.V3_0)]
    public async Task Exact_Iss_Is_Accepted(SsraaVersion version)
    {
        var validator = CreateValidator(version);

        Assert.True(await validator.ValidateJwtToken(SignedMetadata(BaseUrl, BaseUrl), BaseUrl));
    }

    [Theory]
    [InlineData(SsraaVersion.V2_0, "https://A.example.com/fhir")]
    [InlineData(SsraaVersion.V2_0, "https://a.example.com/FHIR")]
    [InlineData(SsraaVersion.V2_0, "https://a.example.com:443/fhir")]
    [InlineData(SsraaVersion.V2_0, "https://a.example.com/fhir/")]
    [InlineData(SsraaVersion.V3_0, "https://A.example.com/fhir")]
    [InlineData(SsraaVersion.V3_0, "https://a.example.com/FHIR")]
    [InlineData(SsraaVersion.V3_0, "https://a.example.com:443/fhir")]
    [InlineData(SsraaVersion.V3_0, "https://a.example.com/fhir/")]
    public async Task Base_Url_Variant_Of_Iss_Is_Rejected(SsraaVersion version, string baseUrl)
    {
        var validator = CreateValidator(version);
        string? error = null;
        validator.TokenError += message => error = message;

        Assert.False(await validator.ValidateJwtToken(SignedMetadata(BaseUrl, BaseUrl), baseUrl));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("https://A.example.com/fhir")]
    [InlineData("https://a.example.com/FHIR")]
    [InlineData("https://a.example.com/fhir/")]
    public async Task Base_Url_Case_And_Trailing_Slash_Variants_Are_Accepted_Under_V1_1(string baseUrl)
    {
        var validator = CreateValidator(SsraaVersion.V1_1);

        Assert.True(await validator.ValidateJwtToken(SignedMetadata(BaseUrl, BaseUrl), baseUrl));
    }

    /// <summary>
    /// The iss must equal a URI SAN verbatim. SSRAA 1.1 accepted a host-only SAN with or without a trailing slash.
    /// </summary>
    [Theory]
    [InlineData(SsraaVersion.V1_1, true)]
    [InlineData(SsraaVersion.V2_0, false)]
    public async Task Iss_Without_Slash_Against_Host_Only_San_With_Slash(SsraaVersion version, bool expected)
    {
        var validator = CreateValidator(version);

        var metadata = SignedMetadata(san: "https://host.example.com/", iss: "https://host.example.com");

        Assert.Equal(expected, await validator.ValidateJwtToken(metadata, "https://host.example.com"));
    }

    [Theory]
    [InlineData(SsraaVersion.V2_0)]
    [InlineData(SsraaVersion.V3_0)]
    public async Task Iss_Differing_From_San_Only_In_Case_Is_Rejected(SsraaVersion version)
    {
        var validator = CreateValidator(version);

        var metadata = SignedMetadata(san: BaseUrl, iss: "https://a.example.com/FHIR");

        Assert.False(await validator.ValidateJwtToken(metadata, "https://a.example.com/FHIR"));
    }

    [Fact]
    public async Task V3_0_Rejects_A_Base_Url_With_Trailing_Slash_Even_When_Iss_Matches()
    {
        const string slashed = "https://a.example.com/fhir/";
        var validator = CreateValidator(SsraaVersion.V3_0);
        string? error = null;
        validator.TokenError += message => error = message;

        Assert.False(await validator.ValidateJwtToken(SignedMetadata(slashed, slashed), slashed));
        Assert.NotNull(error);
        Assert.Contains("must not end in '/'", error);
    }

    [Fact]
    public async Task V2_0_Accepts_A_Base_Url_With_Trailing_Slash_When_Iss_Matches_Exactly()
    {
        const string slashed = "https://a.example.com/fhir/";
        var validator = CreateValidator(SsraaVersion.V2_0);

        Assert.True(await validator.ValidateJwtToken(SignedMetadata(slashed, slashed), slashed));
    }

    [Theory]
    [InlineData("https://a.example.com/fhir/")]
    [InlineData("https://a.example.com/fhir/.well-known/udap")]
    public async Task UdapClient_V3_0_Rejects_Trailing_Slash_Base_Url_Before_Fetching(string address)
    {
        // A base URL whose discovery path follows the slash separator is fine; only the FHIR base URL itself matters.
        var expectRejected = !address.Contains(".well-known");
        var handler = new CountingHandler();
        var validator = CreateValidator(SsraaVersion.V3_0);
        var udapClient = CreateClient(handler, validator);
        string? error = null;
        udapClient.TokenError += message => error = message;

        var disco = await udapClient.ValidateResource(address, (ITrustAnchorStore?)null);

        Assert.True(disco.IsError);
        if (expectRejected)
        {
            Assert.Equal(0, handler.Calls);
            Assert.NotNull(error);
            Assert.Contains("must not end in '/'", disco.Error);
        }
        else
        {
            Assert.Equal(1, handler.Calls);
        }
    }

    [Fact]
    public async Task UdapClient_DiscoveryPolicy_SsraaVersion_Opts_Back_To_V1_1()
    {
        var handler = new CountingHandler();
        var validator = CreateValidator(null);
        var udapClient = CreateClient(handler, validator);

        var policy = DiscoveryPolicy.DefaultMetadataServerPolicy();
        policy.SsraaVersion = SsraaVersion.V1_1;

        await udapClient.ValidateResource("https://a.example.com/fhir/", null, policy);

        Assert.Equal(SsraaVersion.V1_1, validator.SsraaVersion);
        Assert.Equal(1, handler.Calls);
    }

    /// <summary>
    /// The server picks the SAN for the signed metadata iss; it may tolerate a caller's trailing slash when
    /// choosing, but returns the SAN verbatim.
    /// </summary>
    [Fact]
    public void ResolveUriSubjAltName_Returns_San_Verbatim()
    {
        using var certificate = CreateCertificate(BaseUrl, out _);

        Assert.Equal(BaseUrl, certificate.ResolveUriSubjAltName(BaseUrl));
        Assert.Equal(BaseUrl, certificate.ResolveUriSubjAltName(BaseUrl + "/"));
    }

    [Fact]
    public void HasUriSubjectAltName_Is_Ordinal()
    {
        using var certificate = CreateCertificate(BaseUrl, out _);

        Assert.True(certificate.HasUriSubjectAltName(BaseUrl));
        Assert.False(certificate.HasUriSubjectAltName("https://A.example.com/fhir"));
        Assert.False(certificate.HasUriSubjectAltName(BaseUrl + "/"));
        Assert.False(certificate.HasUriSubjectAltName("https://a.example.com:443/fhir"));
    }

    /// <summary>
    /// SSRAA 3.0.0: the metadata server does not advertise a FHIR base URL (the signed metadata iss, taken
    /// verbatim from the certificate SAN) that ends in "/".
    /// </summary>
    [Theory]
    [InlineData(SsraaVersion.V3_0, "https://a.example.com/fhir/", false)]
    [InlineData(SsraaVersion.V3_0, "https://a.example.com/fhir", true)]
    [InlineData(SsraaVersion.V2_0, "https://a.example.com/fhir/", true)]
    [InlineData(SsraaVersion.V1_1, "https://a.example.com/fhir/", true)]
    public async Task MetadataBuilder_Refuses_A_Trailing_Slash_Iss_Under_V3_0(SsraaVersion version, string san, bool signed)
    {
        const string community = "udap://ssraa.test/";
        var certificate = CreateCertificate(san, out _);

        var options = new UdapMetadataOptions
        {
            SsraaVersion = version,
            RegistrationEndpointJwtSigningAlgValuesSupported = [UdapConstants.SupportedAlgorithm.RS256],
            UdapMetadataConfigs =
            [
                new UdapMetadataConfig
                {
                    Community = community,
                    SignedMetadataConfig = new SignedMetadataConfig
                    {
                        AuthorizationEndpoint = "https://auth.example.com/connect/authorize",
                        TokenEndpoint = "https://auth.example.com/connect/token",
                        RegistrationEndpoint = "https://auth.example.com/connect/register"
                    }
                }
            ]
        };

        var provider = Substitute.For<IUdapMetadataOptionsProvider>();
        provider.Value.Returns(options);

        var store = Substitute.For<IPrivateCertificateStore>();
        store.IssuedCertificates = new List<IssuedCertificate> { new(certificate, community) };
        store.Resolve(Arg.Any<CancellationToken>()).Returns(store);

        var builder = new UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>(
            provider, store, Substitute.For<ILogger<UdapMetaDataBuilder<UdapMetadataOptions, UdapMetadata>>>());

        var metadata = await builder.SignMetaData("https://a.example.com/fhir", community);

        Assert.Equal(signed, metadata != null);
        if (metadata != null)
        {
            Assert.Equal(san, new JsonWebToken(metadata.SignedMetadata).Issuer);
        }
    }

    [Fact]
    public void UdapMetadataOptions_SsraaVersion_Reads_From_Json_As_A_String()
    {
        var options = System.Text.Json.JsonSerializer.Deserialize<UdapMetadataOptions>("""{ "SsraaVersion": "V1_1" }""");

        Assert.Equal(SsraaVersion.V1_1, options!.SsraaVersion);
    }

    private static UdapClientDiscoveryValidator CreateValidator(SsraaVersion? version)
    {
        var validator = new UdapClientDiscoveryValidator(
            new TrustChainValidator(Substitute.For<ILogger<TrustChainValidator>>()),
            Substitute.For<ILogger<UdapClientDiscoveryValidator>>());

        if (version.HasValue)
        {
            validator.SsraaVersion = version.Value;
        }

        return validator;
    }

    private static UdapClient CreateClient(HttpMessageHandler handler, UdapClientDiscoveryValidator validator)
    {
        var options = Substitute.For<IOptionsMonitor<UdapClientOptions>>();
        options.CurrentValue.Returns(new UdapClientOptions());

        return new UdapClient(
            new HttpClient(handler),
            validator,
            options,
            Substitute.For<ILogger<UdapClient>>());
    }

    private static UdapMetadata SignedMetadata(string san, string iss)
    {
        using var certificate = CreateCertificate(san, out var key);

        var now = DateTime.UtcNow;
        var signedMetadata = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = iss,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = new Dictionary<string, object> { { "sub", iss }, { "jti", Guid.NewGuid().ToString() } },
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", new[] { Convert.ToBase64String(certificate.RawData) } } },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)
        });

        key.Dispose();

        return new UdapMetadata
        {
            SignedMetadata = signedMetadata,
            RegistrationEndpointJwtSigningAlgValuesSupported = [UdapConstants.SupportedAlgorithm.RS256]
        };
    }

    /// <summary>
    /// Self-signed certificate whose URI SAN is written verbatim (SubjectAlternativeNameBuilder.AddUri would
    /// add a "/" to a host-only URI).
    /// </summary>
    private static X509Certificate2 CreateCertificate(string sanUri, out RSA key)
    {
        key = RSA.Create(2048);
        var request = new CertificateRequest("CN=SSRAA URI test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, sanUri, new Asn1Tag(TagClass.ContextSpecific, 6));
        }
        request.CertificateExtensions.Add(new X509Extension("2.5.29.17", writer.Encode(), false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request });
        }
    }
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Registration;
using Udap.Server.Stores.InMemory;
using Udap.Tefca.Model;
using Udap.Tefca.Server;
using Xunit;

namespace UdapServer.Tests.Validators;

/// <summary>
/// Registration enforcement of required certifications, and the TEFCA Basic App Certification profile.
/// </summary>
public class CertificationsRequiredValidatorTests
{
    private const string Community = TefcaConstants.CommunityUri;
    private const string ClientUri = "https://app.example.com/fhir#T-TREAT";
    private const string RegistrationEndpoint = "https://as.example.com/connect/register";
    private const string OtherCertificationUri = "https://certifier.example.com/udap/profiles/other";

    private static readonly TestPki Pki = new();

    #region Opt-in

    [Fact]
    public void NoRequirement_DoesNotApply()
    {
        var validator = CreateValidator(new ServerSettings(), tefcaOptions: new TefcaValidationOptions());

        Assert.False(validator.AppliesToCommunity(Community));
    }

    [Fact]
    public void ServerSettingsRequirement_AppliesOnlyToItsCommunity()
    {
        var validator = CreateValidator(RequireBasicApp());

        Assert.True(validator.AppliesToCommunity(Community));
        Assert.False(validator.AppliesToCommunity("udap://other.example.com"));
    }

    [Fact]
    public void TefcaOption_RequiresBasicAppCertification()
    {
        var validator = CreateValidator(
            new ServerSettings(),
            tefcaOptions: new TefcaValidationOptions { RequireBasicAppCertification = true });

        Assert.Equal(
            [TefcaConstants.Certification.BasicAppCertificationUri],
            validator.GetRequiredCertificationUris(Community));
    }

    [Fact]
    public void AddUdapServerConfiguration_RegistersCertificationsRequiredValidator()
    {
        var services = new ServiceCollection();
        services.AddUdapServerBuilder().AddUdapServerConfiguration();

        Assert.Contains(services, sd =>
            sd.ServiceType == typeof(ICommunityRegistrationValidator) &&
            sd.ImplementationType == typeof(UdapCertificationsRequiredValidator));
    }

    [Fact]
    public void AddUdapTefcaValidation_RegistersBasicAppCertificationValidator()
    {
        var services = new ServiceCollection();
        services.AddUdapTefcaValidation();

        var provider = services.BuildServiceProvider();
        var profileValidator = provider.GetService<IUdapCertificationProfileValidator>();

        Assert.IsType<TefcaBasicAppCertificationValidator>(profileValidator);
        Assert.False(profileValidator.IsRequiredForCommunity(Community));
    }

    #endregion

    #region Generic certification checks

    [Fact]
    public async Task ValidCertification_IsAccepted()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification();
        var context = CreateContext(certification);

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
        var accepted = Assert.IsAssignableFrom<IReadOnlyList<UdapValidatedCertification>>(
            context.Items[UdapCertificationsRequiredValidator.ValidatedCertificationsItemKey]);
        Assert.Equal(certification, Assert.Single(accepted).Certification);
    }

    [Fact]
    public async Task ValidCertification_RequiredByTefcaOption_IsAccepted()
    {
        var validator = CreateValidator(
            new ServerSettings(),
            tefcaOptions: new TefcaValidationOptions { RequireBasicAppCertification = true });

        var result = await validator.ValidateAsync(CreateContext(BasicAppCertification()));

        Assert.Null(result);
    }

    [Fact]
    public async Task MissingCertification_IsUnapproved()
    {
        var validator = CreateValidator(RequireBasicApp());

        var result = await validator.ValidateAsync(CreateContext());

        AssertError(result, UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
            TefcaConstants.Certification.BasicAppCertificationUri);
    }

    [Fact]
    public async Task WrongCertificationUri_IsUnapproved()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(uris: [OtherCertificationUri]);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement,
            TefcaConstants.Certification.BasicAppCertificationUri);
    }

    [Fact]
    public async Task OneOfSeveralCertifications_SatisfiesRequirement()
    {
        var validator = CreateValidator(RequireBasicApp());
        var context = CreateContext(
            BasicAppCertification(uris: [OtherCertificationUri]),
            BasicAppCertification());

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task BadSignature_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = TamperPayload(BasicAppCertification());

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "signature");
    }

    [Fact]
    public async Task ExpiredCertification_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(expiration: TimeSpan.FromMinutes(-10));

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "expired");
    }

    [Fact]
    public async Task UntrustedCertifier_IsUnapproved()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(signer: Pki.UntrustedClient);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement, "not trusted");
    }

    [Fact]
    public async Task SubjectNotClient_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification();
        var context = CreateContextForIssuer("https://other-app.example.com/fhir#T-TREAT", certification);

        var result = await validator.ValidateAsync(context);

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "sub");
    }

    [Fact]
    public async Task AudienceForOtherServer_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(audience: "https://other-as.example.com/connect/register");

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "aud");
    }

    [Fact]
    public async Task AudienceForThisServer_IsAccepted()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(audience: RegistrationEndpoint);

        var result = await validator.ValidateAsync(CreateContext(certification));

        Assert.Null(result);
    }

    #endregion

    #region TEFCA Basic App Certification profile

    [Fact]
    public async Task QualifiedExchangePurpose_IsAccepted()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(
            exchangePurposes: [$"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-TREAT"]);

        var result = await validator.ValidateAsync(CreateContext(certification));

        Assert.Null(result);
    }

    [Fact]
    public async Task MismatchedExchangePurpose_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(exchangePurposes: [TefcaConstants.ExchangePurposeCodes.Payment]);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "does not match");
    }

    [Fact]
    public async Task ExchangePurposeFromOtherCodeSystem_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(exchangePurposes: ["urn:oid:1.2.3#T-TREAT"]);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "does not match");
    }

    [Fact]
    public async Task TwoExchangePurposes_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(exchangePurposes:
            [TefcaConstants.ExchangePurposeCodes.Treatment, TefcaConstants.ExchangePurposeCodes.Payment]);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "exactly one");
    }

    [Fact]
    public async Task MissingExchangePurposes_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(omitExchangePurposes: true);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "exactly one");
    }

    [Fact]
    public async Task WrongCertificationName_IsInvalid()
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(name: "Some Other Certification");

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "certification_name");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("1.2.3.4.5")]
    [InlineData("urn:oid:")]
    [InlineData("urn:oid:not-an-oid")]
    public async Task MissingOrMalformedHomeCommunityId_IsInvalid(string? homeCommunityId)
    {
        var validator = CreateValidator(RequireBasicApp());
        var certification = BasicAppCertification(homeCommunityId: homeCommunityId);

        var result = await validator.ValidateAsync(CreateContext(certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "home_community_id");
    }

    [Fact]
    public async Task NonTefcaCommunity_RequiringBasicAppUri_GetsGenericChecksOnly()
    {
        const string otherCommunity = "udap://other.example.com";
        var validator = CreateValidator(RequireBasicAppIn(otherCommunity));

        // Fails every TEFCA rule, but is a valid generic certification chained to the other community's anchor.
        var certification = BasicAppCertification(
            signer: Pki.UntrustedClient,
            name: "Some Other Certification",
            omitExchangePurposes: true,
            homeCommunityId: null);

        var result = await validator.ValidateAsync(
            CreateContextForCommunity(otherCommunity, 2, ClientUri, certification));

        Assert.Null(result);
    }

    [Fact]
    public async Task NonTefcaCommunity_RequiringBasicAppUri_StillRejectsExpiredCertification()
    {
        const string otherCommunity = "udap://other.example.com";
        var validator = CreateValidator(RequireBasicAppIn(otherCommunity));
        var certification = BasicAppCertification(signer: Pki.UntrustedClient, expiration: TimeSpan.FromMinutes(-10));

        var result = await validator.ValidateAsync(
            CreateContextForCommunity(otherCommunity, 2, ClientUri, certification));

        AssertError(result, UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, "expired");
    }

    [Fact]
    public void BasicAppProfile_AppliesOnlyToTefcaCommunities()
    {
        var profileValidator = new TefcaBasicAppCertificationValidator(Options.Create(new TefcaValidationOptions()));

        Assert.True(profileValidator.AppliesToCommunity(Community));
        Assert.False(profileValidator.AppliesToCommunity("udap://other.example.com"));
    }

    #endregion

    #region Helpers

    private static ServerSettings RequireBasicAppIn(string communityName) => new()
    {
        CommunityCertificationsRequired =
        [
            new UdapCertificationRequirement
            {
                Community = communityName,
                CertificationUris = [TefcaConstants.Certification.BasicAppCertificationUri]
            }
        ]
    };

    private static ServerSettings RequireBasicApp() => new()
    {
        CommunityCertificationsRequired =
        [
            new UdapCertificationRequirement
            {
                Community = Community,
                CertificationUris = [TefcaConstants.Certification.BasicAppCertificationUri]
            }
        ]
    };

    private static UdapCertificationsRequiredValidator CreateValidator(
        ServerSettings serverSettings,
        TefcaValidationOptions? tefcaOptions = null)
    {
        var community = new Community
        {
            Id = 1,
            Name = Community,
            Enabled = true,
            Anchors = [new Anchor(Pki.TrustedCa, Community, "Trusted CA") { Enabled = true, CommunityId = 1 }]
        };

        var untrustedCommunity = new Community
        {
            Id = 2,
            Name = "udap://other.example.com",
            Enabled = true,
            Anchors = [new Anchor(Pki.UntrustedCa, "udap://other.example.com", "Other CA") { Enabled = true, CommunityId = 2 }]
        };

        var store = new InMemoryUdapClientRegistrationStore(
            new List<Client>(),
            new List<Udap.Common.Models.TieredClient>(),
            [community, untrustedCommunity]);

        // Certificate revocation is offline for unit tests.
        var trustChainValidator = new TrustChainValidator(
            ChainProblemStatus.NotTimeValid |
            ChainProblemStatus.Revoked |
            ChainProblemStatus.NotSignatureValid |
            ChainProblemStatus.InvalidBasicConstraints,
            false,
            NullLogger<TrustChainValidator>.Instance);

        var profileValidators = new IUdapCertificationProfileValidator[]
        {
            new TefcaBasicAppCertificationValidator(Options.Create(tefcaOptions ?? new TefcaValidationOptions()))
        };

        return new UdapCertificationsRequiredValidator(
            serverSettings,
            profileValidators,
            store,
            trustChainValidator,
            NullLogger<UdapCertificationsRequiredValidator>.Instance);
    }

    private static UdapDynamicClientRegistrationContext CreateContext(params string[] certifications)
        => CreateContextForIssuer(ClientUri, certifications);

    private static UdapDynamicClientRegistrationContext CreateContextForIssuer(string issuer, params string[] certifications)
        => CreateContextForCommunity(Community, 1, issuer, certifications);

    private static UdapDynamicClientRegistrationContext CreateContextForCommunity(
        string communityName,
        long communityId,
        string issuer,
        params string[] certifications)
    {
        return new UdapDynamicClientRegistrationContext
        {
            Request = new UdapRegisterRequest("software-statement", UdapConstants.UdapVersionsSupportedValue, certifications),
            Issuer = issuer,
            CommunityName = communityName,
            CommunityId = communityId,
            Document = new UdapDynamicClientRegistrationDocument { Audience = RegistrationEndpoint }
        };
    }

    private static string BasicAppCertification(
        X509Certificate2? signer = null,
        string name = TefcaConstants.Certification.BasicAppCertificationName,
        ICollection<string>? uris = null,
        TimeSpan? expiration = null,
        string? audience = null,
        string[]? exchangePurposes = null,
        bool omitExchangePurposes = false,
        string? homeCommunityId = "urn:oid:2.16.840.1.113883.3.7204.1.1.1.1")
    {
        var additionalClaims = new Dictionary<string, JsonElement>();
        exchangePurposes ??= [TefcaConstants.ExchangePurposeCodes.Treatment];

        if (!omitExchangePurposes)
        {
            additionalClaims[TefcaConstants.Certification.ExchangePurposes] = JsonSerializer.SerializeToElement(exchangePurposes);
        }

        if (homeCommunityId != null)
        {
            additionalClaims[TefcaConstants.Certification.HomeCommunityId] = JsonSerializer.SerializeToElement(homeCommunityId);
        }

        return UdapCertificationsAndEndorsementBuilder
            .Create(name, signer ?? Pki.Client)
            .WithCertificationUris(uris ?? [TefcaConstants.Certification.BasicAppCertificationUri])
            .WithExpiration(expiration ?? TimeSpan.FromDays(30))
            .WithAudience(audience)
            .WithAdditionalClaims(additionalClaims)
            .BuildSoftwareStatement();
    }

    private static string TamperPayload(string jws)
    {
        var parts = jws.Split('.');
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
        payload = payload.Replace("TEFCA Basic App Certification", "TEFCA Basic App Certificatio_");
        parts[1] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));

        return string.Join('.', parts);
    }

    private static void AssertError(
        UdapDynamicClientRegistrationValidationResult? result,
        string error,
        string descriptionFragment)
    {
        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Equal(error, result.Error);
        Assert.Contains(descriptionFragment, result.ErrorDescription);
    }

    /// <summary>
    /// A trusted CA and an untrusted CA, each issuing a client certificate whose SAN carries an exchange purpose.
    /// </summary>
    private sealed class TestPki
    {
        public TestPki()
        {
            TrustedCa = CreateCa("CN=Certification Test Trusted CA");
            UntrustedCa = CreateCa("CN=Certification Test Untrusted CA");
            Client = CreateClient(TrustedCa, ClientUri);
            UntrustedClient = CreateClient(UntrustedCa, ClientUri);
        }

        public X509Certificate2 TrustedCa { get; }
        public X509Certificate2 UntrustedCa { get; }
        public X509Certificate2 Client { get; }
        public X509Certificate2 UntrustedClient { get; }

        private static X509Certificate2 CreateCa(string subject)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));

            return Reload(ca);
        }

        // Round-trip through PKCS#12 so the private key outlives the RSA instance on every platform.
        private static X509Certificate2 Reload(X509Certificate2 certificate)
        {
            var pfx = certificate.Export(X509ContentType.Pfx, "test");
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(pfx, "test", X509KeyStorageFlags.Exportable);
#else
            return new X509Certificate2(pfx, "test", X509KeyStorageFlags.Exportable);
#endif
        }

        private static X509Certificate2 CreateClient(X509Certificate2 issuer, string sanUri)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=Certification Test Client", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));

            var san = new SubjectAlternativeNameBuilder();
            san.AddUri(new Uri(sanUri));
            request.CertificateExtensions.Add(san.Build());

            var serial = new byte[16];
            RandomNumberGenerator.Fill(serial);
            serial[0] &= 0x7F;

            using var publicOnly = request.Create(
                issuer,
                DateTimeOffset.UtcNow.AddHours(-1),
                DateTimeOffset.UtcNow.AddYears(1),
                serial);

            using var withKey = publicOnly.CopyWithPrivateKey(key);

            return Reload(withKey);
        }
    }

    #endregion
}

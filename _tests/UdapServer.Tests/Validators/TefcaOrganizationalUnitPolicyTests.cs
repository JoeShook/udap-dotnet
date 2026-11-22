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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Registration;
using Udap.Server.Validation;
using Udap.Tefca.Model;
using Udap.Tefca.Server;
using Udap.Util.Extensions;
using Xunit;

namespace UdapServer.Tests.Validators;

/// <summary>
/// Optional subject OU policy binding for TEFCA communities
/// (<see cref="TefcaValidationOptions.RequiredCertificateOrganizationalUnits"/>).
/// Certificates are built in-test because the generated test PKI does not carry the TEFCA OUs.
/// </summary>
public class TefcaOrganizationalUnitPolicyTests
{
    private const string ProductionCommunity = TefcaConstants.CommunityUri;
    private const string ValidationCommunity = "urn:oid:2.999.1.5.test";
    private const string SanUri = "urn:oid:2.999#T-TRTMNT";

    private static IOptions<TefcaValidationOptions> PolicyOptions()
    {
        var options = new TefcaValidationOptions();
        options.Communities.Add(ValidationCommunity);
        options.RequiredCertificateOrganizationalUnits[ProductionCommunity] =
            [TefcaConstants.OrganizationalUnits.Production];
        options.RequiredCertificateOrganizationalUnits[ValidationCommunity] =
            [TefcaConstants.OrganizationalUnits.Validation];

        return Options.Create(options);
    }

    #region Certificate OU extraction

    [Fact]
    public void GetSubjectOrganizationalUnits_ReturnsEveryOu()
    {
        using var cert = CreateCertificate("CN=client, OU=Other Unit, OU=RCE-FHIR, O=FhirLabs");

        var units = cert.GetSubjectOrganizationalUnits();

        Assert.Equal(2, units.Count);
        Assert.Contains("Other Unit", units);
        Assert.Contains(TefcaConstants.OrganizationalUnits.Production, units);
    }

    [Fact]
    public void GetSubjectOrganizationalUnits_NoOu_ReturnsEmpty()
    {
        using var cert = CreateCertificate("CN=client, O=FhirLabs");

        Assert.Empty(cert.GetSubjectOrganizationalUnits());
    }

    [Fact]
    public void HasSubjectOrganizationalUnit_ExactValueOnly()
    {
        // RCE-FHIR-TEST must not satisfy a policy for RCE-FHIR (and the reverse).
        using var testCert = CreateCertificate("CN=client, OU=RCE-FHIR-TEST");
        using var prodCert = CreateCertificate("CN=client, OU=RCE-FHIR");

        Assert.False(testCert.HasSubjectOrganizationalUnit([TefcaConstants.OrganizationalUnits.Production]));
        Assert.False(prodCert.HasSubjectOrganizationalUnit([TefcaConstants.OrganizationalUnits.Validation]));
        Assert.True(prodCert.HasSubjectOrganizationalUnit(["rce-fhir"]));
    }

    #endregion

    #region Options / DI

    [Fact]
    public void Options_DefaultHasNoOuPolicy()
    {
        var options = new TefcaValidationOptions();

        Assert.Empty(options.RequiredCertificateOrganizationalUnits);
    }

    [Fact]
    public void AddUdapTefcaValidation_ConfiguresOuPolicy()
    {
        var services = new ServiceCollection();

        services.AddUdapTefcaValidation(options =>
        {
            options.RequiredCertificateOrganizationalUnits[TefcaConstants.CommunityUri] =
                [TefcaConstants.OrganizationalUnits.Production];
        });

        var options = services.BuildServiceProvider()
            .GetRequiredService<IOptions<TefcaValidationOptions>>();

        Assert.Contains(
            TefcaConstants.OrganizationalUnits.Production,
            options.Value.RequiredCertificateOrganizationalUnits[TefcaConstants.CommunityUri]);
    }

    #endregion

    #region Registration (software statement x5c[0])

    [Fact]
    public async Task Registration_WithRequiredOu_Succeeds()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, cert));

        Assert.Null(result);
    }

    [Fact]
    public async Task Registration_OneOfSeveralOusMatches_Succeeds()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=Direct, OU=RCE-FHIR, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, cert));

        Assert.Null(result);
    }

    [Fact]
    public async Task Registration_WithoutOu_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, cert));

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Equal(UdapDynamicClientRegistrationErrors.UnapprovedSoftwareStatement, result.Error);
        Assert.Contains(TefcaConstants.OrganizationalUnits.Production, result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_ProductionOuInValidationCommunity_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ValidationCommunity, cert));

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Contains(TefcaConstants.OrganizationalUnits.Validation, result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_ValidationOuInProductionCommunity_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR-TEST, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, cert));

        Assert.NotNull(result);
        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Registration_ValidationOuInValidationCommunity_Succeeds()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR-TEST, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ValidationCommunity, cert));

        Assert.Null(result);
    }

    [Fact]
    public async Task Registration_MissingCertificate_WithPolicy_IsRejected()
    {
        var validator = new TefcaRegistrationValidator(PolicyOptions());

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, null));

        Assert.NotNull(result);
        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Registration_NoPolicy_CertificateWithoutOu_Succeeds()
    {
        // Off by default: current behaviour is preserved.
        var validator = new TefcaRegistrationValidator(Options.Create(new TefcaValidationOptions()));
        using var cert = CreateCertificate("CN=client, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, cert));

        Assert.Null(result);
    }

    [Fact]
    public async Task Registration_EmptyOuSet_IsNotEnforced()
    {
        var options = new TefcaValidationOptions();
        options.RequiredCertificateOrganizationalUnits[ProductionCommunity] = [];
        var validator = new TefcaRegistrationValidator(Options.Create(options));
        using var cert = CreateCertificate("CN=client, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateRegistrationContext(ProductionCommunity, cert));

        Assert.Null(result);
    }

    #endregion

    #region Token endpoint (client assertion x5c[0])

    [Fact]
    public async Task Token_WithRequiredOu_Succeeds()
    {
        var validator = new TefcaTokenValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateTokenContext(ProductionCommunity, cert));

        Assert.True(result.IsValid, result.ErrorDescription);
    }

    [Fact]
    public async Task Token_WithoutOu_IsRejected()
    {
        var validator = new TefcaTokenValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateTokenContext(ProductionCommunity, cert));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_client", result.Error);
        Assert.Contains(TefcaConstants.OrganizationalUnits.Production, result.ErrorDescription);
    }

    [Fact]
    public async Task Token_ProductionOuInValidationCommunity_IsRejected()
    {
        var validator = new TefcaTokenValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateTokenContext(ValidationCommunity, cert));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_client", result.Error);
    }

    [Fact]
    public async Task Token_ValidationOuInProductionCommunity_IsRejected()
    {
        var validator = new TefcaTokenValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR-TEST, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateTokenContext(ProductionCommunity, cert));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_client", result.Error);
    }

    [Fact]
    public async Task Token_ValidationOuInValidationCommunity_Succeeds()
    {
        var validator = new TefcaTokenValidator(PolicyOptions());
        using var cert = CreateCertificate("CN=client, OU=RCE-FHIR-TEST, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateTokenContext(ValidationCommunity, cert));

        Assert.True(result.IsValid, result.ErrorDescription);
    }

    [Fact]
    public async Task Token_ClientAssertionWithoutX5c_WithPolicy_IsRejected()
    {
        var validator = new TefcaTokenValidator(PolicyOptions());

        var result = await validator.ValidateAsync(CreateTokenContext(ProductionCommunity, null));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_client", result.Error);
    }

    [Fact]
    public async Task Token_NoPolicy_CertificateWithoutOu_Succeeds()
    {
        var validator = new TefcaTokenValidator(Options.Create(new TefcaValidationOptions()));
        using var cert = CreateCertificate("CN=client, O=FhirLabs");

        var result = await validator.ValidateAsync(CreateTokenContext(ProductionCommunity, cert));

        Assert.True(result.IsValid, result.ErrorDescription);
    }

    #endregion

    #region Helpers

    private static X509Certificate2 CreateCertificate(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static UdapDynamicClientRegistrationContext CreateRegistrationContext(
        string communityName,
        X509Certificate2? certificate)
    {
        return new UdapDynamicClientRegistrationContext
        {
            Request = new UdapRegisterRequest(),
            Issuer = SanUri,
            CommunityName = communityName,
            ClientCertificate = certificate
        };
    }

    private static UdapAuthorizationExtensionValidationContext CreateTokenContext(
        string communityName,
        X509Certificate2? certificate)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "test-client",
            Claims = new Dictionary<string, object> { ["sub"] = "test-client" }
        };

        if (certificate != null)
        {
            descriptor.AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["x5c"] = new[] { Convert.ToBase64String(certificate.RawData) }
            };
        }

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(handler.CreateToken(descriptor));

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "Organization/1.2.3",
            OrganizationName = "Test Org"
        };
        b2b.PurposeOfUse!.Add("T-TRTMNT");

        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwt,
            ClientId = "test-client",
            Extensions = new Dictionary<string, object>
            {
                [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
            },
            CommunityId = "1",
            CommunityName = communityName,
            GrantType = "client_credentials",
            SanUri = SanUri
        };
    }

    #endregion
}

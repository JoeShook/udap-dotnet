#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Registration;
using Udap.Server.Validation;
using Udap.Tefca.Model;
using Udap.Tefca.Server;
using Xunit;

namespace UdapServer.Tests.Validators;

public class TefcaCommunityValidatorTests
{
    #region TefcaRegistrationValidator

    [Theory]
    [InlineData("T-TRTMNT")]
    [InlineData("T-TREAT")]
    [InlineData("T-PYMNT")]
    [InlineData("T-HCO")]
    [InlineData("T-HCO-CC")]
    [InlineData("T-HCO-HED")]
    [InlineData("T-HCO-QM")]
    [InlineData("T-PH")]
    [InlineData("T-PH-ECR")]
    [InlineData("T-PH-ELR")]
    [InlineData("T-IAS")]
    [InlineData("T-GOVDTRM")]
    public async Task Registration_ValidExchangePurpose_Succeeds(string xpCode)
    {
        var validator = new TefcaRegistrationValidator();
        var context = CreateRegistrationContext($"urn:oid:2.999#{xpCode}");

        var result = await validator.ValidateAsync(context);

        Assert.Null(result); // null = success
    }

    [Fact]
    public async Task Registration_InvalidExchangePurpose_IsRejected()
    {
        var validator = new TefcaRegistrationValidator();
        var context = CreateRegistrationContext("urn:oid:2.999#INVALID");

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Contains("INVALID", result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_SanUriWithoutFragment_IsRejected()
    {
        var validator = new TefcaRegistrationValidator();
        var context = CreateRegistrationContext("urn:oid:2.999");

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Contains("exchange purpose code after '#'", result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_EmptyIssuer_IsRejected()
    {
        var validator = new TefcaRegistrationValidator();
        var context = CreateRegistrationContext(null);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Registration_TrailingHash_IsRejected()
    {
        var validator = new TefcaRegistrationValidator();
        var context = CreateRegistrationContext("urn:oid:2.999#");

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.True(result.IsError);
    }

    [Fact]
    public void Registration_AppliesToTefcaCommunity()
    {
        var validator = new TefcaRegistrationValidator();

        Assert.True(validator.AppliesToCommunity(TefcaConstants.CommunityUri));
        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
        Assert.False(validator.AppliesToCommunity("udap://Provider2"));
    }

    #endregion

    #region TefcaTokenValidator

    [Fact]
    public async Task Token_MatchingPurposeOfUse_Succeeds()
    {
        var validator = new TefcaTokenValidator();
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-TREAT");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_MatchingPurposeOfUse_BareCode_Succeeds()
    {
        var validator = new TefcaTokenValidator();
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TRTMNT",
            purposeOfUse: "T-TRTMNT");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Token_MismatchedPurposeOfUse_IsRejected()
    {
        var validator = new TefcaTokenValidator();
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-PYMNT");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("T-PYMNT", result.ErrorDescription);
        Assert.Contains("T-TREAT", result.ErrorDescription);
    }

    [Fact]
    public async Task Token_NoRegisteredSanUri_IsRejected()
    {
        var validator = new TefcaTokenValidator();
        var context = CreateTokenContext(
            sanUri: null,
            purposeOfUse: "T-TREAT");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
    }

    [Fact]
    public async Task Token_SanUriWithoutFragment_IsRejected()
    {
        var validator = new TefcaTokenValidator();
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999",
            purposeOfUse: "T-TREAT");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Token_NoExtensions_Succeeds()
    {
        var validator = new TefcaTokenValidator();
        var context = CreateTokenContext(
            sanUri: "urn:oid:2.999#T-TREAT",
            purposeOfUse: null); // no extensions at all

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Token_AppliesToTefcaCommunity()
    {
        var validator = new TefcaTokenValidator();

        Assert.True(validator.AppliesToCommunity(TefcaConstants.CommunityUri));
        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
    }

    #endregion

    #region Regression — non-TEFCA communities

    [Fact]
    public void Registration_NonTefcaCommunity_NotApplicable()
    {
        var validator = new TefcaRegistrationValidator();

        // Validator should not apply, so it would never be called
        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
    }

    [Fact]
    public void Token_NonTefcaCommunity_NotApplicable()
    {
        var validator = new TefcaTokenValidator();

        Assert.False(validator.AppliesToCommunity("udap://fhirlabs1/"));
    }

    #endregion

    #region Helpers

    private static UdapDynamicClientRegistrationContext CreateRegistrationContext(string? issuer)
    {
        return new UdapDynamicClientRegistrationContext
        {
            Request = new UdapRegisterRequest(),
            Issuer = issuer,
            CommunityName = TefcaConstants.CommunityUri
        };
    }

    private static UdapAuthorizationExtensionValidationContext CreateTokenContext(
        string? sanUri,
        string? purposeOfUse)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(
            handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "test-client",
                Claims = new Dictionary<string, object> { ["sub"] = "test-client" }
            }));

        Dictionary<string, object>? extensions = null;

        if (purposeOfUse != null)
        {
            var b2b = new HL7B2BAuthorizationExtension
            {
                OrganizationId = "Organization/1.2.3",
                OrganizationName = "Test Org"
            };
            b2b.PurposeOfUse!.Add(purposeOfUse);

            extensions = new Dictionary<string, object>
            {
                [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
            };
        }

        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwt,
            ClientId = "test-client",
            Extensions = extensions,
            CommunityId = "1",
            CommunityName = TefcaConstants.CommunityUri,
            GrantType = "client_credentials",
            SanUri = sanUri
        };
    }

    #endregion
}

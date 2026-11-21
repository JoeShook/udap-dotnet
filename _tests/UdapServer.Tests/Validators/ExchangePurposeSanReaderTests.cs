#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

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
using Xunit;

namespace UdapServer.Tests.Validators;

public class ExchangePurposeSanReaderTests
{
    #region Fragment (default)

    [Fact]
    public void Options_DefaultLocation_IsFragment()
    {
        var options = new TefcaValidationOptions();

        Assert.Equal(ExchangePurposeLocation.Fragment, options.ExchangePurposeLocation);
        Assert.Equal("xp", options.ExchangePurposeQueryParameter);
    }

    [Theory]
    [InlineData("urn:oid:2.999#T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://example.com/fhir#T-TREAT", "T-TREAT")]
    [InlineData("https://example.com/fhir?xp=T-PYMNT#T-IAS", "T-IAS")]
    public void Fragment_ValidCode_IsRead(string sanUri, string expected)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.Fragment);

        Assert.True(result.IsValid);
        Assert.Equal(expected, result.Code);
    }

    [Theory]
    [InlineData("urn:oid:2.999")]
    [InlineData("urn:oid:2.999#")]
    [InlineData("https://example.com/fhir/T-TRTMNT")]
    [InlineData("https://example.com/fhir?xp=T-TRTMNT")]
    [InlineData("")]
    [InlineData(null)]
    public void Fragment_NoFragment_IsMissing(string? sanUri)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.Fragment);

        Assert.False(result.IsValid);
        Assert.Equal(ExchangePurposeReadStatus.Missing, result.Status);
    }

    [Theory]
    [InlineData("urn:oid:2.999#INVALID", "INVALID")]
    [InlineData("urn:oid:2.999#T-HCO-QM", "T-HCO-QM")]
    [InlineData("urn:oid:2.999#t-trtmnt", "t-trtmnt")]
    public void Fragment_UnknownCode_IsInvalid(string sanUri, string rejected)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.Fragment);

        Assert.Equal(ExchangePurposeReadStatus.Invalid, result.Status);
        Assert.Equal(rejected, result.Code);
        Assert.Contains(rejected, result.ErrorDescription);
    }

    #endregion

    #region Path segment

    [Theory]
    [InlineData("https://example.com/fhir/T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://example.com/T-TREAT/fhir", "T-TREAT")]
    [InlineData("https://example.com/fhir/T-IAS/", "T-IAS")]
    [InlineData("https://example.com/fhir/T-PYMNT?xp=T-HCO#T-PH", "T-PYMNT")]
    [InlineData("https://example.com/fhir/T-HCO/T-HCO", "T-HCO")]
    [InlineData("urn:oid:2.999/T-TRTMNT", "T-TRTMNT")]
    public void PathSegment_ValidCode_IsRead(string sanUri, string expected)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.PathSegment);

        Assert.True(result.IsValid);
        Assert.Equal(expected, result.Code);
    }

    [Theory]
    [InlineData("urn:oid:2.999#T-TRTMNT")]
    [InlineData("https://example.com/fhir?xp=T-TRTMNT")]
    [InlineData("https://example.com/fhir/INVALID")]
    [InlineData("https://example.com/fhir/T-HCO-QM")]
    [InlineData("https://T-TRTMNT/fhir")]
    [InlineData("https://example.com")]
    public void PathSegment_NoCodeInPath_IsMissing(string sanUri)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.PathSegment);

        Assert.False(result.IsValid);
        Assert.Equal(ExchangePurposeReadStatus.Missing, result.Status);
    }

    [Fact]
    public void PathSegment_TwoDifferentCodes_IsAmbiguous()
    {
        var result = ExchangePurposeSanReader.Read(
            "https://example.com/T-TREAT/T-PYMNT", ExchangePurposeLocation.PathSegment);

        Assert.Equal(ExchangePurposeReadStatus.Ambiguous, result.Status);
        Assert.Null(result.Code);
    }

    #endregion

    #region Query parameter

    [Theory]
    [InlineData("https://example.com/fhir?xp=T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://example.com/fhir?a=1&xp=T-TREAT&b=2", "T-TREAT")]
    [InlineData("https://example.com/fhir?xp=T-IAS#T-PH", "T-IAS")]
    [InlineData("https://example.com/fhir?xp=T-IAS&xp=T-IAS", "T-IAS")]
    [InlineData("urn:oid:2.999?xp=T-PYMNT", "T-PYMNT")]
    public void QueryParameter_ValidCode_IsRead(string sanUri, string expected)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.QueryParameter, "xp");

        Assert.True(result.IsValid);
        Assert.Equal(expected, result.Code);
    }

    [Fact]
    public void QueryParameter_CustomName_IsRead()
    {
        var options = new TefcaValidationOptions
        {
            ExchangePurposeLocation = ExchangePurposeLocation.QueryParameter,
            ExchangePurposeQueryParameter = "purpose"
        };

        var result = ExchangePurposeSanReader.Read("https://example.com/fhir?xp=T-PH&purpose=T-HCO", options);

        Assert.True(result.IsValid);
        Assert.Equal("T-HCO", result.Code);
    }

    [Theory]
    [InlineData("urn:oid:2.999#T-TRTMNT")]
    [InlineData("https://example.com/fhir/T-TRTMNT")]
    [InlineData("https://example.com/fhir?other=T-TRTMNT")]
    [InlineData("https://example.com/fhir?XP=T-TRTMNT")]
    [InlineData("https://example.com/fhir?xp=")]
    [InlineData("https://example.com/fhir?xp")]
    [InlineData("https://example.com/fhir#?xp=T-TRTMNT")]
    public void QueryParameter_NoParameter_IsMissing(string sanUri)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, ExchangePurposeLocation.QueryParameter, "xp");

        Assert.False(result.IsValid);
        Assert.Equal(ExchangePurposeReadStatus.Missing, result.Status);
    }

    [Fact]
    public void QueryParameter_UnknownCode_IsInvalid()
    {
        var result = ExchangePurposeSanReader.Read(
            "https://example.com/fhir?xp=INVALID", ExchangePurposeLocation.QueryParameter, "xp");

        Assert.Equal(ExchangePurposeReadStatus.Invalid, result.Status);
        Assert.Equal("INVALID", result.Code);
    }

    [Fact]
    public void QueryParameter_RepeatedWithDifferentValues_IsAmbiguous()
    {
        var result = ExchangePurposeSanReader.Read(
            "https://example.com/fhir?xp=T-TREAT&xp=T-PYMNT", ExchangePurposeLocation.QueryParameter, "xp");

        Assert.Equal(ExchangePurposeReadStatus.Ambiguous, result.Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void QueryParameter_NoNameConfigured_IsMissing(string? name)
    {
        var result = ExchangePurposeSanReader.Read(
            "https://example.com/fhir?xp=T-TREAT", ExchangePurposeLocation.QueryParameter, name);

        Assert.Equal(ExchangePurposeReadStatus.Missing, result.Status);
    }

    #endregion

    #region Every known code is accepted at every location

    public static IEnumerable<object[]> AllCodesAtAllLocations()
    {
        foreach (var code in TefcaConstants.ExchangePurposeCodes.All)
        {
            yield return [ExchangePurposeLocation.Fragment, $"urn:oid:2.999#{code}", code];
            yield return [ExchangePurposeLocation.PathSegment, $"https://example.com/fhir/{code}", code];
            yield return [ExchangePurposeLocation.QueryParameter, $"https://example.com/fhir?xp={code}", code];
        }
    }

    [Theory]
    [MemberData(nameof(AllCodesAtAllLocations))]
    public void EveryKnownCode_IsRead(ExchangePurposeLocation location, string sanUri, string expected)
    {
        var result = ExchangePurposeSanReader.Read(sanUri, location, "xp");

        Assert.True(result.IsValid);
        Assert.Equal(expected, result.Code);
    }

    #endregion

    #region Registration and token validation agree

    public static IEnumerable<object?[]> SanUrisForEveryLocation()
    {
        var sanUris = new[]
        {
            "urn:oid:2.999#T-TRTMNT",
            "urn:oid:2.999#INVALID",
            "urn:oid:2.999",
            "https://example.com/fhir/T-TRTMNT",
            "https://example.com/fhir/INVALID",
            "https://example.com/T-TREAT/T-PYMNT",
            "https://example.com/fhir?xp=T-TRTMNT",
            "https://example.com/fhir?xp=INVALID",
            "https://example.com/fhir?xp=T-TREAT&xp=T-PYMNT",
        };

        foreach (var location in Enum.GetValues<ExchangePurposeLocation>())
        {
            foreach (var sanUri in sanUris)
            {
                yield return [location, sanUri];
            }
        }
    }

    [Theory]
    [MemberData(nameof(SanUrisForEveryLocation))]
    public async Task RegistrationAndToken_AgreeOnSanUri(ExchangePurposeLocation location, string sanUri)
    {
        var options = Options.Create(new TefcaValidationOptions { ExchangePurposeLocation = location });
        var expected = ExchangePurposeSanReader.Read(sanUri, options.Value);

        var registrationResult = await new TefcaRegistrationValidator(options)
            .ValidateAsync(CreateRegistrationContext(sanUri));

        // Use the code read from the SAN (or a placeholder) as purpose_of_use so a valid
        // registration also yields a valid token request.
        var tokenResult = await new TefcaTokenValidator(options)
            .ValidateAsync(CreateTokenContext(sanUri, expected.Code ?? "T-TRTMNT"));

        Assert.Equal(expected.IsValid, registrationResult == null);
        Assert.Equal(expected.IsValid, tokenResult.IsValid);
    }

    [Theory]
    [InlineData(ExchangePurposeLocation.Fragment, "urn:oid:2.999#T-TRTMNT")]
    [InlineData(ExchangePurposeLocation.PathSegment, "https://example.com/fhir/T-TRTMNT")]
    [InlineData(ExchangePurposeLocation.QueryParameter, "https://example.com/fhir?xp=T-TRTMNT")]
    public async Task SelectedLocation_AcceptsOnlyThatForm(ExchangePurposeLocation selected, string sanUri)
    {
        foreach (var location in Enum.GetValues<ExchangePurposeLocation>())
        {
            var options = Options.Create(new TefcaValidationOptions { ExchangePurposeLocation = location });

            var registrationResult = await new TefcaRegistrationValidator(options)
                .ValidateAsync(CreateRegistrationContext(sanUri));
            var tokenResult = await new TefcaTokenValidator(options)
                .ValidateAsync(CreateTokenContext(sanUri, "T-TRTMNT"));

            var shouldAccept = location == selected;
            Assert.Equal(shouldAccept, registrationResult == null);
            Assert.Equal(shouldAccept, tokenResult.IsValid);
        }
    }

    [Fact]
    public async Task Token_PathSegment_MismatchedPurposeOfUse_IsRejected()
    {
        var options = Options.Create(new TefcaValidationOptions
        {
            ExchangePurposeLocation = ExchangePurposeLocation.PathSegment
        });

        var result = await new TefcaTokenValidator(options).ValidateAsync(
            CreateTokenContext("https://example.com/fhir/T-TREAT",
                $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#T-PYMNT"));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("T-PYMNT", result.ErrorDescription);
        Assert.Contains("T-TREAT", result.ErrorDescription);
    }

    [Fact]
    public async Task Token_QueryParameter_IasClientCredentialsWithoutTefcaIas_IsRejected()
    {
        var options = Options.Create(new TefcaValidationOptions
        {
            ExchangePurposeLocation = ExchangePurposeLocation.QueryParameter
        });

        var result = await new TefcaTokenValidator(options).ValidateAsync(
            CreateTokenContext("https://example.com/fhir?xp=T-IAS", "T-IAS"));

        Assert.False(result.IsValid);
        Assert.Contains("tefca_ias", result.ErrorDescription);
    }

    [Fact]
    public async Task Registration_PathSegment_Missing_ExplainsLocation()
    {
        var options = Options.Create(new TefcaValidationOptions
        {
            ExchangePurposeLocation = ExchangePurposeLocation.PathSegment
        });

        var result = await new TefcaRegistrationValidator(options)
            .ValidateAsync(CreateRegistrationContext("urn:oid:2.999#T-TRTMNT"));

        Assert.NotNull(result);
        Assert.True(result.IsError);
        Assert.Contains("path", result.ErrorDescription);
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

    private static UdapAuthorizationExtensionValidationContext CreateTokenContext(string? sanUri, string purposeOfUse)
    {
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(
            handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "test-client",
                Claims = new Dictionary<string, object> { ["sub"] = "test-client" }
            }));

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "Organization/1.2.3",
            OrganizationName = "Test Org"
        };
        b2b.PurposeOfUse!.Add(purposeOfUse);

        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwt,
            ClientId = "test-client",
            Extensions = new Dictionary<string, object>
            {
                [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
            },
            CommunityId = "1",
            CommunityName = TefcaConstants.CommunityUri,
            GrantType = "client_credentials",
            SanUri = sanUri
        };
    }

    #endregion
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using NSubstitute;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Configuration;
using Udap.Server.Storage.Stores;
using Udap.Server.Validation;
using Udap.Server.Validation.Default;
using Udap.Tefca.Model;
using UdapServer.Tests.Common;

namespace UdapServer.Tests.Validators;

public class DefaultUdapAuthorizationExtensionValidatorTests
{
    private readonly ILogger<DefaultUdapAuthorizationExtensionValidator> _logger =
        Substitute.For<ILogger<DefaultUdapAuthorizationExtensionValidator>>();

    #region No Required Extensions

    [Fact]
    public async Task NoRequiredExtensions_NoExtensionsPresent_Succeeds()
    {
        var validator = CreateValidator(new ServerSettings());
        var context = CreateContext();

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NoRequiredExtensions_ExtensionsPresent_Succeeds()
    {
        var validator = CreateValidator(new ServerSettings());
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NullRequiredExtensions_Succeeds()
    {
        var settings = new ServerSettings { AuthorizationExtensionsRequired = null };
        var validator = CreateValidator(settings);
        var context = CreateContext();

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task EmptyRequiredExtensions_Succeeds()
    {
        var settings = new ServerSettings { AuthorizationExtensionsRequired = [] };
        var validator = CreateValidator(settings);
        var context = CreateContext();

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region Required Extension Presence

    [Fact]
    public async Task RequiredExtension_Missing_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext();

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task RequiredExtension_NullExtensions_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: null);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("missing", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequiredExtension_EmptyExtensions_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: new Dictionary<string, object>());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
    }

    [Fact]
    public async Task RequiredExtension_Present_Succeeds()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task MultipleRequiredExtensions_OneMissing_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired =
            [
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
                UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER
            ]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task RequiredExtension_WrongKeyPresent_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    #endregion

    #region Structural Validation

    [Fact]
    public async Task B2BExtension_MissingOrganizationId_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = null
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("organization_id", result.ErrorDescription);
    }

    [Fact]
    public async Task B2BExtension_MissingPurposeOfUse_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        // PurposeOfUse is initialized to empty collection in constructor

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("purpose_of_use", result.ErrorDescription);
    }

    [Fact]
    public async Task B2BExtension_MissingVersion_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);

        var b2b = new HL7B2BAuthorizationExtension
        {
            Version = "",
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("version", result.ErrorDescription);
    }

    [Fact]
    public async Task B2BExtension_AllRequiredFieldsPresent_Succeeds()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task B2BUserExtension_MissingUserPerson_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);

        var b2bUser = new HL7B2BUserAuthorizationExtension();
        b2bUser.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER] = b2bUser
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("user_person", result.ErrorDescription);
    }

    [Fact]
    public async Task UnknownExtensionType_NotStructurallyValidated_Succeeds()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = ["custom-extension"]
        };
        var validator = CreateValidator(settings);

        var extensions = new Dictionary<string, object>
        {
            ["custom-extension"] = new { version = "1", custom_field = "value" }
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region Community Settings

    [Fact]
    public async Task CommunityValidator_MatchingCommunity_UsesValidatorRules()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings { AuthorizationExtensionsRequired = null }, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_MatchingCommunity_WithValidExtension_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings { AuthorizationExtensionsRequired = null }, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_NonMatchingCommunity_FallsBackToGlobal()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        // Community "2" resolves to a name that no validator matches
        clientStore.GetCommunityName("2").Returns(Task.FromResult<string?>("udap://community-b"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-b").Returns(false);

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "2");

        var result = await validator.ValidateAsync(context);

        // Falls back to global which requires hl7-b2b
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_NullCommunityId_FallsBackToGlobal()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };

        var validator = CreateValidator(settings);
        var context = CreateContext(communityId: null);

        var result = await validator.ValidateAsync(context);

        // Falls back to global which requires hl7-b2b
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_RulesOverrideGlobal_EmptyRequired_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string>() // empty — no extensions required
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        // Community validator's empty required set overrides global requirement
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_NullRules_FallsBackToGlobal()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        // Community validator returned null rules — falls back to global
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_MultipleCommunities_CorrectOneSelected()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));
        clientStore.GetCommunityName("2").Returns(Task.FromResult<string?>("udap://community-b"));

        var validatorA = Substitute.For<ICommunityTokenValidator>();
        validatorA.AppliesToCommunity("udap://community-a").Returns(true);
        validatorA.AppliesToCommunity("udap://community-b").Returns(false);
        validatorA.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B }
        });

        var validatorB = Substitute.For<ICommunityTokenValidator>();
        validatorB.AppliesToCommunity("udap://community-a").Returns(false);
        validatorB.AppliesToCommunity("udap://community-b").Returns(true);
        validatorB.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string>
            {
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
                TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS
            }
        });
        validatorB.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        // Client in community-b should need both hl7-b2b and tefca-ias
        var validator = CreateValidator(new ServerSettings(), clientStore, [validatorA, validatorB]);
        var context = CreateContext(communityId: "2", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("tefca-ias", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_CommunityNameNotResolved_FallsBackToGlobal()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>(null));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        // Community name didn't resolve, falls back to global
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    #endregion

    #region Grant Type Specific Extensions

    [Fact]
    public async Task GrantTypeSpecific_ClientCredentials_RequiresB2B_Succeeds()
    {
        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions(), grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_ClientCredentials_MissingB2B_Fails()
    {
        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_RequiresB2BUser_Succeeds()
    {
        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);

        var b2bUser = new HL7B2BUserAuthorizationExtension();
        b2bUser.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2bUser.UserPerson = JsonDocument.Parse("{}").RootElement;

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER] = b2bUser
        };
        var context = CreateContext(extensions: extensions, grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_MissingB2BUser_Fails()
    {
        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_AuthorizationCode_WrongExtension_Fails()
    {
        // Client sends hl7-b2b but authorization_code requires hl7-b2b-user
        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions(), grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_SSRAA_AuthorizationCode_NoExtensionRequired_Succeeds()
    {
        // SSRAA requires hl7-b2b for client_credentials but NOT for authorization_code
        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
            // AuthorizationCodeExtensionsRequired is null — no extension needed
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(grantType: "authorization_code"); // no extensions

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_FallsBackToGeneral_WhenNoGrantSpecific()
    {
        // Only general AuthorizationExtensionsRequired set, no grant-specific
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_OverridesGeneral()
    {
        // General requires hl7-b2b, but grant-specific for client_credentials is empty
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            ClientCredentialsExtensionsRequired = []
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        // Grant-specific empty set overrides the general requirement
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_ClientCredentials_RequiresB2B()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings(), clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "Organization/1.2.3",
            OrganizationName = "Test QHIN"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "10", extensions: extensions, grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_AuthorizationCode_RequiresB2BUser()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings(), clientStore, [communityValidator]);

        // Client sends hl7-b2b (wrong for authorization_code)
        var context = CreateContext(communityId: "10", extensions: CreateValidB2BExtensions(), grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_NullGrantRules_FallsBackToGlobal()
    {
        // Community validator applies but returns null rules for the grant type — falls back to global
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        // Falls back to global's AuthorizationExtensionsRequired
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    #endregion

    #region Purpose of Use Validation (via Community Validators)

    // POU validation is the responsibility of community validators via GetValidationRules.
    // The base validator enforces AllowedPurposeOfUse/MaxPurposeOfUseCount from the
    // community validator's rules. Without a community validator, no POU validation occurs.

    [Fact]
    public async Task CommunityValidator_AllowedPurposeOfUse_ValidCode_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT", "urn:oid:2.16.840.1.113883.5.8#ETREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings(), clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_AllowedPurposeOfUse_DisallowedCode_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = new HashSet<string> { "urn:oid:2.16.840.1.113883.5.8#ETREAT" }
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings(), clientStore, [communityValidator]);
        // CreateValidB2BExtensions uses TREAT, which is not in the allowed set
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("TREAT", result.ErrorDescription);
        Assert.Contains("disallowed", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidator_NullAllowList_AnyCodeAccepted()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            AllowedPurposeOfUse = null
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings(), clientStore, [communityValidator]);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidator_MaxPurposeOfUseCount_ExceedsLimit_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("1").Returns(Task.FromResult<string?>("udap://community-a"));

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("udap://community-a").Returns(true);
        communityValidator.GetValidationRules("client_credentials").Returns(new CommunityValidationRules
        {
            RequiredExtensions = new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            MaxPurposeOfUseCount = 1
        });
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(new ServerSettings(), clientStore, [communityValidator]);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#ETREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "1", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("maximum allowed is 1", result.ErrorDescription);
    }

    [Fact]
    public async Task NoCommunityValidator_NoPOUValidation()
    {
        // Without a community validator, no POU validation occurs
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        };
        var validator = CreateValidator(settings);

        // Any POU code is accepted when no community validator applies
        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#ETREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#HPAYMT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    #endregion

    #region ErrorExtensions

    /// <summary>
    /// Validates that <see cref="AuthorizationExtensionValidationResult.ErrorExtensions"/>
    /// can carry custom error data for trust community profiles.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">
    /// SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 B2B #3, Table 1</a>
    /// </summary>
    [Fact]
    public void ErrorExtensions_Failure_Factory_Carries_Extensions()
    {
        var errorExtensions = new Dictionary<string, object>
        {
            ["hl7-b2b"] = new
            {
                consent_required = new[] { "urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1" },
                consent_form = "https://tefca.example.com/consent/form.pdf"
            }
        };

        var result = AuthorizationExtensionValidationResult.Failure(
            "invalid_grant",
            "Consent policy required",
            errorExtensions);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Equal("Consent policy required", result.ErrorDescription);
        Assert.NotNull(result.ErrorExtensions);
        Assert.True(result.ErrorExtensions.ContainsKey("hl7-b2b"));
    }

    [Fact]
    public void ErrorExtensions_Standard_Failure_Has_Null_Extensions()
    {
        var result = AuthorizationExtensionValidationResult.Failure(
            "invalid_grant",
            "Missing required extension");

        Assert.False(result.IsValid);
        Assert.Null(result.ErrorExtensions);
    }

    [Fact]
    public void ErrorExtensions_Success_Has_Null_Extensions()
    {
        var result = AuthorizationExtensionValidationResult.Success();

        Assert.True(result.IsValid);
        Assert.Null(result.ErrorExtensions);
    }

    #endregion

    #region CommunityValidatorsAlwaysRun

    [Fact]
    public async Task CommunityValidators_RunEvenWhenNoExtensionsRequired_AuthorizationCode()
    {
        // Arrange: no AuthorizationCodeExtensionsRequired, but a community validator is registered
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var settings = new ServerSettings
        {
            ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
            // AuthorizationCodeExtensionsRequired is null — no extension needed
        };

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant", "community validator rejected")));

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "10", grantType: "authorization_code");

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert: community validator was invoked and its rejection is returned
        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("community validator rejected", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityValidators_RunEvenWhenNoExtensionsRequired_Success()
    {
        // Arrange: community validator returns success
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var settings = new ServerSettings();

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(true);
        communityValidator.GetValidationRules("authorization_code").Returns((CommunityValidationRules?)null);
        communityValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(Task.FromResult(AuthorizationExtensionValidationResult.Success()));

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "10", grantType: "authorization_code");

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityValidators_NotInvokedForNonMatchingCommunity()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityName("10").Returns(Task.FromResult<string?>("urn:oid:2.16.840.1.113883.3.7204.1.5"));

        var settings = new ServerSettings();

        var communityValidator = Substitute.For<ICommunityTokenValidator>();
        communityValidator.AppliesToCommunity("urn:oid:2.16.840.1.113883.3.7204.1.5").Returns(false);

        var validator = CreateValidator(settings, clientStore, [communityValidator]);
        var context = CreateContext(communityId: "10", grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
        await communityValidator.DidNotReceive().ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>());
    }

    #endregion

    #region Helpers

    private DefaultUdapAuthorizationExtensionValidator CreateValidator(
        ServerSettings settings,
        IUdapClientRegistrationStore? clientStore = null)
    {
        return CreateValidator(settings, clientStore, null);
    }

    private DefaultUdapAuthorizationExtensionValidator CreateValidator(
        ServerSettings settings,
        IUdapClientRegistrationStore? clientStore,
        IEnumerable<ICommunityTokenValidator>? communityValidators)
    {
        var optionsMonitor = new OptionsMonitorForTests<ServerSettings>(settings);
        clientStore ??= Substitute.For<IUdapClientRegistrationStore>();

        return new DefaultUdapAuthorizationExtensionValidator(optionsMonitor, clientStore, communityValidators ?? Enumerable.Empty<ICommunityTokenValidator>(), _logger);
    }

    private static UdapAuthorizationExtensionValidationContext CreateContext(
        Dictionary<string, object>? extensions = null,
        string? communityId = null,
        string clientId = "test-client",
        string grantType = "client_credentials")
    {
        // Create a minimal valid JWT for the context
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(
            handler.CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Issuer = clientId,
                Claims = new Dictionary<string, object> { ["sub"] = clientId }
            }));

        return new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwt,
            ClientId = clientId,
            Extensions = extensions,
            CommunityId = communityId,
            GrantType = grantType
        };
    }

    private static Dictionary<string, object> CreateValidB2BExtensions()
    {
        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4/Organization/99",
            OrganizationName = "FhirLabs"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        return new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
    }

    #endregion
}

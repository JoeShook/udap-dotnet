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
    public async Task CommunityOverride_MatchingCommunity_UsesOverrideSettings()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = null,
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityOverride_MatchingCommunity_WithValidExtension_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = null,
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
                    AllowedPurposeOfUse = ["urn:oid:2.16.840.1.113883.5.8#TREAT"]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityOverride_NonMatchingCommunity_FallsBackToGlobal()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = null
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        // Client is in community 2, which doesn't match any CommunitySettings
        var context = CreateContext(communityId: "2");

        var result = await validator.ValidateAsync(context);

        // Falls back to global which requires hl7-b2b
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityOverride_NullCommunityId_FallsBackToGlobal()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = []
                }
            ]
        };

        var validator = CreateValidator(settings);
        var context = CreateContext(communityId: null);

        var result = await validator.ValidateAsync(context);

        // Falls back to global which requires hl7-b2b
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task CommunityOverride_OverrideHasNoRequired_GlobalHasRequired_UsesOverride()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = []
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        // Community override has empty required list — no extensions needed
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CommunityOverride_NullOverrideRequired_FallsBackToGlobal()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = null
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        // Community override has null required — falls back to global
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityOverride_MultipleCommunities_CorrectOneSelected()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));
        clientStore.GetCommunityId("udap://community-b")
            .Returns(Task.FromResult<int?>(2));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = null,
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
                },
                new CommunityServerSettings
                {
                    Community = "udap://community-b",
                    AuthorizationExtensionsRequired =
                    [
                        UdapConstants.UdapAuthorizationExtensions.Hl7B2B,
                        UdapConstants.UdapAuthorizationExtensions.TEFCAIAS
                    ]
                }
            ]
        };

        // Client in community-b should need both hl7-b2b and tefca-ias
        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "2", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("tefca-ias", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityOverride_CommunityNotFoundInStore_FallsBackToGlobal()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(null));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = []
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1");

        var result = await validator.ValidateAsync(context);

        // Community name didn't resolve to an ID that matches "1", falls back to global
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
        clientStore.GetCommunityId("urn:oid:2.16.840.1.113883.3.7204.1.5")
            .Returns(Task.FromResult<int?>(10));

        var settings = new ServerSettings
        {
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "urn:oid:2.16.840.1.113883.3.7204.1.5",
                    ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
                    AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER],
                    AllowedPurposeOfUse =
                    [
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT"
                    ]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);

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
        clientStore.GetCommunityId("urn:oid:2.16.840.1.113883.3.7204.1.5")
            .Returns(Task.FromResult<int?>(10));

        var settings = new ServerSettings
        {
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "urn:oid:2.16.840.1.113883.3.7204.1.5",
                    ClientCredentialsExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
                    AuthorizationCodeExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);

        // Client sends hl7-b2b (wrong for authorization_code)
        var context = CreateContext(communityId: "10", extensions: CreateValidB2BExtensions(), grantType: "authorization_code");

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b-user", result.ErrorDescription);
    }

    [Fact]
    public async Task GrantTypeSpecific_Community_FallsBackToGeneralCommunity()
    {
        // Community has AuthorizationExtensionsRequired but no grant-specific
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1", grantType: "client_credentials");

        var result = await validator.ValidateAsync(context);

        // Falls back to community's general AuthorizationExtensionsRequired
        Assert.False(result.IsValid);
        Assert.Contains("hl7-b2b", result.ErrorDescription);
    }

    #endregion

    #region Purpose of Use Validation

    [Fact]
    public async Task AllowedPurposeOfUse_ValidCode_Succeeds()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AllowedPurposeOfUse = ["urn:oid:2.16.840.1.113883.5.8#TREAT", "urn:oid:2.16.840.1.113883.5.8#ETREAT"]
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task AllowedPurposeOfUse_DisallowedCode_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AllowedPurposeOfUse = ["urn:oid:2.16.840.1.113883.5.8#ETREAT"]
        };
        var validator = CreateValidator(settings);
        // CreateValidB2BExtensions uses TREAT, which is not in the allowed set
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("invalid_grant", result.Error);
        Assert.Contains("TREAT", result.ErrorDescription);
        Assert.Contains("disallowed", result.ErrorDescription);
    }

    [Fact]
    public async Task AllowedPurposeOfUse_NullAllowList_AnyCodeAccepted()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AllowedPurposeOfUse = null
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task AllowedPurposeOfUse_EmptyAllowList_AllCodesRejected()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AllowedPurposeOfUse = []
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("disallowed", result.ErrorDescription);
    }

    [Fact]
    public async Task MaxPurposeOfUseCount_WithinLimit_Succeeds()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            MaxPurposeOfUseCount = 2
        };
        var validator = CreateValidator(settings);
        var context = CreateContext(extensions: CreateValidB2BExtensions()); // has 1

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task MaxPurposeOfUseCount_ExceedsLimit_Fails()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            MaxPurposeOfUseCount = 1
        };
        var validator = CreateValidator(settings);

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
        var context = CreateContext(extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("maximum allowed is 1", result.ErrorDescription);
    }

    [Fact]
    public async Task MaxPurposeOfUseCount_Null_NoLimit()
    {
        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            MaxPurposeOfUseCount = null
        };
        var validator = CreateValidator(settings);

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

    [Fact]
    public async Task TefcaStyle_MaxCount1_AllowedXPCodes_ValidRequest_Succeeds()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("urn:oid:2.16.840.1.113883.3.7204.1.5")
            .Returns(Task.FromResult<int?>(10));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "urn:oid:2.16.840.1.113883.3.7204.1.5",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
                    MaxPurposeOfUseCount = 1,
                    AllowedPurposeOfUse =
                    [
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT",
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT",
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-PYMNT",
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-IAS"
                    ]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);

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
        var context = CreateContext(communityId: "10", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task TefcaStyle_MaxCount1_MultiplePurposes_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("urn:oid:2.16.840.1.113883.3.7204.1.5")
            .Returns(Task.FromResult<int?>(10));

        var settings = new ServerSettings
        {
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "urn:oid:2.16.840.1.113883.3.7204.1.5",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
                    MaxPurposeOfUseCount = 1,
                    AllowedPurposeOfUse =
                    [
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT",
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-PYMNT"
                    ]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "Organization/1.2.3",
            OrganizationName = "Test QHIN"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT");
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-PYMNT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "10", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("maximum allowed is 1", result.ErrorDescription);
    }

    [Fact]
    public async Task TefcaStyle_WrongCodeSystem_Fails()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("urn:oid:2.16.840.1.113883.3.7204.1.5")
            .Returns(Task.FromResult<int?>(10));

        var settings = new ServerSettings
        {
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "urn:oid:2.16.840.1.113883.3.7204.1.5",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
                    AllowedPurposeOfUse =
                    [
                        "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT"
                    ]
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);

        // Client sends HL7 v3 PurposeOfUse code instead of TEFCA XP code
        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "Organization/1.2.3",
            OrganizationName = "Test QHIN"
        };
        b2b.PurposeOfUse!.Add("urn:oid:2.16.840.1.113883.5.8#TREAT");

        var extensions = new Dictionary<string, object>
        {
            [UdapConstants.UdapAuthorizationExtensions.Hl7B2B] = b2b
        };
        var context = CreateContext(communityId: "10", extensions: extensions);

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Contains("disallowed", result.ErrorDescription);
        Assert.Contains("2.16.840.1.113883.5.8#TREAT", result.ErrorDescription);
    }

    [Fact]
    public async Task CommunityOverride_PurposeOfUse_NullAllowList_FailsWithConfigError()
    {
        var clientStore = Substitute.For<IUdapClientRegistrationStore>();
        clientStore.GetCommunityId("udap://community-a")
            .Returns(Task.FromResult<int?>(1));

        var settings = new ServerSettings
        {
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B],
            AllowedPurposeOfUse = ["urn:oid:2.16.840.1.113883.5.8#ETREAT"],
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://community-a",
                    AllowedPurposeOfUse = null // no fallback to global — must be configured
                }
            ]
        };

        var validator = CreateValidator(settings, clientStore);
        var context = CreateContext(communityId: "1", extensions: CreateValidB2BExtensions());

        var result = await validator.ValidateAsync(context);

        Assert.False(result.IsValid);
        Assert.Equal("server_error", result.Error);
        Assert.Contains("AllowedPurposeOfUse is not configured", result.ErrorDescription);
    }

    #endregion

    #region Helpers

    private DefaultUdapAuthorizationExtensionValidator CreateValidator(
        ServerSettings settings,
        IUdapClientRegistrationStore? clientStore = null)
    {
        var optionsMonitor = new OptionsMonitorForTests<ServerSettings>(settings);
        clientStore ??= Substitute.For<IUdapClientRegistrationStore>();

        return new DefaultUdapAuthorizationExtensionValidator(optionsMonitor, clientStore, _logger);
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

#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using FluentAssertions;
using System.Text.Json;

namespace UdapMetadata.Tests;

public class UdapMetadataTests
{
    [Fact]
    public void UdapMetadata_Properties_Set_Correctly()
    {
        // Arrange
        var udapVersionsSupported = new List<string> { "1.0" };
        var udapProfilesSupported = new List<string> { "udap_dcr", "udap_authn" };
        var udapAuthorizationExtensionsSupported = new List<string> { "hl7-b2b" };
        var udapAuthorizationExtensionsRequired = new List<string> { "hl7-b2b" };
        var udapCertificationsSupported = new List<string> { "https://www.example.com/udap/profiles/example-certification" };
        var udapCertificationsRequired = new List<string> { "https://www.example.com/udap/profiles/example-certification" };
        var grantTypesSupported = new List<string> { "authorization_code", "refresh_token", "client_credentials" };
        var scopesSupported = new List<string> { "openid", "launch/patient" };
        var tokenEndpointAuthMethodsSupported = new List<string> { "private_key_jwt" };
        var tokenEndpointAuthSigningAlgValuesSupported = new List<string> { "RS256", "ES384" };
        var registrationEndpointJwtSigningAlgValuesSupported = new List<string> { "RS256", "ES384" };

        // Act
        var udapMetadata = new Udap.Model.UdapMetadata(
            udapVersionsSupported,
            udapProfilesSupported,
            udapAuthorizationExtensionsSupported,
            udapAuthorizationExtensionsRequired,
            udapCertificationsSupported,
            udapCertificationsRequired,
            grantTypesSupported,
            scopesSupported,
            tokenEndpointAuthMethodsSupported,
            tokenEndpointAuthSigningAlgValuesSupported,
            registrationEndpointJwtSigningAlgValuesSupported
        );

        // Assert
        udapMetadata.UdapVersionsSupported.Should().BeEquivalentTo(udapVersionsSupported);
        udapMetadata.UdapProfilesSupported.Should().BeEquivalentTo(udapProfilesSupported);
        udapMetadata.UdapAuthorizationExtensionsSupported.Should().BeEquivalentTo(udapAuthorizationExtensionsSupported);
        udapMetadata.UdapAuthorizationExtensionsRequired.Should().BeEquivalentTo(udapAuthorizationExtensionsRequired);
        udapMetadata.UdapCertificationsSupported.Should().BeEquivalentTo(udapCertificationsSupported);
        udapMetadata.UdapCertificationsRequired.Should().BeEquivalentTo(udapCertificationsRequired);
        udapMetadata.GrantTypesSupported.Should().BeEquivalentTo(grantTypesSupported);
        udapMetadata.ScopesSupported.Should().BeEquivalentTo(scopesSupported);
        udapMetadata.TokenEndpointAuthMethodsSupported.Should().BeEquivalentTo(tokenEndpointAuthMethodsSupported);
        udapMetadata.TokenEndpointAuthSigningAlgValuesSupported.Should().BeEquivalentTo(tokenEndpointAuthSigningAlgValuesSupported);
        udapMetadata.RegistrationEndpointJwtSigningAlgValuesSupported.Should().BeEquivalentTo(registrationEndpointJwtSigningAlgValuesSupported);
    }

    [Fact]
    public void UdapMetadata_Property_Setters_Work_Correctly()
    {
        // Arrange
        var udapMetadata = new Udap.Model.UdapMetadata();

        var udapVersionsSupported = new List<string> { "1.0" };
        var udapProfilesSupported = new List<string> { "udap_dcr", "udap_authn" };
        var udapAuthorizationExtensionsSupported = new List<string> { "hl7-b2b" };
        var udapAuthorizationExtensionsRequired = new List<string> { "hl7-b2b" };
        var udapCertificationsSupported = new List<string> { "https://www.example.com/udap/profiles/example-certification" };
        var udapCertificationsRequired = new List<string> { "https://www.example.com/udap/profiles/example-certification" };
        var grantTypesSupported = new List<string> { "authorization_code", "refresh_token", "client_credentials" };
        var scopesSupported = new List<string> { "openid", "launch/patient" };
        var tokenEndpointAuthMethodsSupported = new List<string> { "private_key_jwt" };
        var tokenEndpointAuthSigningAlgValuesSupported = new List<string> { "RS256", "ES384" };
        var registrationEndpointJwtSigningAlgValuesSupported = new List<string> { "RS256", "ES384" };
        var authorizationEndpoint = "https://www.example.com/authorize";
        var tokenEndpoint = "https://www.example.com/token";

        // Act
        udapMetadata.UdapVersionsSupported = udapVersionsSupported;
        udapMetadata.UdapProfilesSupported = udapProfilesSupported;
        udapMetadata.UdapAuthorizationExtensionsSupported = udapAuthorizationExtensionsSupported;
        udapMetadata.UdapAuthorizationExtensionsRequired = udapAuthorizationExtensionsRequired;
        udapMetadata.UdapCertificationsSupported = udapCertificationsSupported;
        udapMetadata.UdapCertificationsRequired = udapCertificationsRequired;
        udapMetadata.GrantTypesSupported = grantTypesSupported;
        udapMetadata.ScopesSupported = scopesSupported;
        udapMetadata.TokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
        udapMetadata.TokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
        udapMetadata.RegistrationEndpointJwtSigningAlgValuesSupported = registrationEndpointJwtSigningAlgValuesSupported;
        udapMetadata.AuthorizationEndpoint = authorizationEndpoint;
        udapMetadata.TokenEndpoint = tokenEndpoint;

        // Assert
        udapMetadata.UdapVersionsSupported.Should().BeEquivalentTo(udapVersionsSupported);
        udapMetadata.UdapProfilesSupported.Should().BeEquivalentTo(udapProfilesSupported);
        udapMetadata.UdapAuthorizationExtensionsSupported.Should().BeEquivalentTo(udapAuthorizationExtensionsSupported);
        udapMetadata.UdapAuthorizationExtensionsRequired.Should().BeEquivalentTo(udapAuthorizationExtensionsRequired);
        udapMetadata.UdapCertificationsSupported.Should().BeEquivalentTo(udapCertificationsSupported);
        udapMetadata.UdapCertificationsRequired.Should().BeEquivalentTo(udapCertificationsRequired);
        udapMetadata.GrantTypesSupported.Should().BeEquivalentTo(grantTypesSupported);
        udapMetadata.ScopesSupported.Should().BeEquivalentTo(scopesSupported);
        udapMetadata.TokenEndpointAuthMethodsSupported.Should().BeEquivalentTo(tokenEndpointAuthMethodsSupported);
        udapMetadata.TokenEndpointAuthSigningAlgValuesSupported.Should().BeEquivalentTo(tokenEndpointAuthSigningAlgValuesSupported);
        udapMetadata.RegistrationEndpointJwtSigningAlgValuesSupported.Should().BeEquivalentTo(registrationEndpointJwtSigningAlgValuesSupported);
        udapMetadata.AuthorizationEndpoint.Should().Be(authorizationEndpoint);
        udapMetadata.TokenEndpoint.Should().Be(tokenEndpoint);
    }

    [Fact]
    public void UdapMetadataOptions_ExtensionData_RoundTrip_Works()
    {
        // Arrange: JSON with an extra property
        var json = @"{
        ""udapVersionsSupported"": [""1.0""],
        ""extra_property"": ""extra_value"",
        ""custom_extensions"": [""https://fhirlabs.net/extension_1"", ""https://fhirlabs.net/extension_2""]
    }";

        // Act: Deserialize to UdapMetadataOptions
        var options = JsonSerializer.Deserialize<Udap.Model.UdapMetadataOptions>(json);

        // Assert: ExtensionData contains the extra property
        options.Should().NotBeNull();
        options!.ExtensionData.Should().NotBeNull();
        options.ExtensionData.Should().ContainKey("extra_property");
        options.ExtensionData["extra_property"].GetString().Should().Be("extra_value");

        var customExtensions = options.ExtensionData["custom_extensions"];
        customExtensions.ValueKind.Should().Be(JsonValueKind.Array);
        var urls = customExtensions.EnumerateArray().Select(e => e.GetString()).ToList();
        urls.Should().BeEquivalentTo(new[] { "https://fhirlabs.net/extension_1", "https://fhirlabs.net/extension_2" });

        // Act: Transfer to UdapMetadata and serialize
        var metadata = new Udap.Model.UdapMetadata(options);
        var serializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
        };
        var serialized = JsonSerializer.Serialize(metadata, serializerOptions);

        // Assert: Serialized JSON contains the extra property in snake_case
        serialized.Should().Contain(@"""extra_property"":""extra_value""");

        serialized.Should().Contain(@"""custom_extensions"":[""https://fhirlabs.net/extension_1"",""https://fhirlabs.net/extension_2""]");
    }
}

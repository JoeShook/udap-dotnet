#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Udap.Model;

namespace Udap.Server.Configuration;
public class ServerSettings
{
    /// <summary>
    /// Specifies which version of the HL7 UDAP Security IG (SSRAA) this server enforces.
    /// Default is <see cref="SsraaVersion.V2_0"/> for new deployments.
    /// Set to <see cref="SsraaVersion.V1_1"/> to allow PKCE and state to remain optional.
    /// </summary>
    [JsonPropertyName("SsraaVersion")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public SsraaVersion SsraaVersion { get; set; } = SsraaVersion.V2_0;

    /// <summary>
    /// Effective PKCE requirement. True when <see cref="SsraaVersion"/> is
    /// <see cref="SsraaVersion.V2_0"/>, or when <see cref="RequirePkce"/> is explicitly set.
    /// </summary>
    [JsonIgnore]
    public bool EffectiveRequirePkce => RequirePkce || SsraaVersion == SsraaVersion.V2_0;

    /// <summary>
    /// Effective state parameter requirement. True when <see cref="SsraaVersion"/> is
    /// <see cref="SsraaVersion.V2_0"/>, or when <see cref="ForceStateParamOnAuthorizationCode"/>
    /// is explicitly set.
    /// </summary>
    [JsonIgnore]
    public bool EffectiveForceState => ForceStateParamOnAuthorizationCode || SsraaVersion == SsraaVersion.V2_0;

    [JsonPropertyName("DefaultSystemScopes")]
    public string? DefaultSystemScopes { get; set; }

    [JsonPropertyName("DefaultUserScopes")]
    public string? DefaultUserScopes { get; set; }

    /// <summary>
    /// Require state param to exist on /connect/authorize? calls.
    /// This is off by default.  When enabled it will only
    /// respond to clients registered with secrets of type
    /// <see>
    ///     <cref>IdentityServerConstants.SecretTypes.Udap_X509_Pem</cref>
    /// </see>
    /// .
    /// </summary>
    [JsonPropertyName("ForceStateParamOnAuthorizationCode")]
    public bool ForceStateParamOnAuthorizationCode { get; set; } = false;

    /// <summary>
    /// Indicate if the IdentityServer can act as a UDAP enabled IdP.
    /// </summary>
    [JsonIgnore]
    public bool TieredIdp { get; set; } = false;

    [JsonPropertyName("LogoRequired")]
    public bool LogoRequired { get; set; } = true;

    /// <summary>
    /// By default the jti claim is required on registration requests.  And replay attacks are monitored.
    /// </summary>
    public bool RegistrationJtiRequired { get; set; } = true;


    public bool AlwaysIncludeUserClaimsInIdToken { get; set; }

    public bool RequireConsent { get; set; } = true;
    public bool AllowRememberConsent { get; set; } = false;

    /// <summary>
    /// Force UDAP clients to register with PKCE regardless of SSRAA version.
    /// </summary>
    public bool RequirePkce { get; set; }
}


public static class ConfigurationExtension
{
    public static TOptions GetOption<TOptions>(this IConfiguration configuration, string settingKey)
        where TOptions : class, new()
    {
        var options = new TOptions();
        configuration.Bind(settingKey, options);
        return options;
    }
}

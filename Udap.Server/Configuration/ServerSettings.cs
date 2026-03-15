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
using Udap.Server.Validation;

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
    /// Effective PKCE requirement. When <see cref="RequirePkce"/> is explicitly set (true or false),
    /// that value is used. Otherwise falls back to <see cref="SsraaVersion"/> policy:
    /// V2_0 requires PKCE, V1_1 does not.
    /// </summary>
    [JsonIgnore]
    public bool EffectiveRequirePkce => RequirePkce ?? (SsraaVersion == SsraaVersion.V2_0);

    /// <summary>
    /// Effective state parameter requirement. When <see cref="ForceStateParamOnAuthorizationCode"/>
    /// is explicitly set (true or false), that value is used. Otherwise falls back to
    /// <see cref="SsraaVersion"/> policy: V2_0 requires state, V1_1 does not.
    /// </summary>
    [JsonIgnore]
    public bool EffectiveForceState => ForceStateParamOnAuthorizationCode ?? (SsraaVersion == SsraaVersion.V2_0);

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
    public bool? ForceStateParamOnAuthorizationCode { get; set; }

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
    /// Explicitly control PKCE requirement. When set to true, PKCE is required regardless of
    /// SSRAA version. When set to false, PKCE is not required even with V2_0. When null (default),
    /// falls back to <see cref="SsraaVersion"/> policy.
    /// </summary>
    public bool? RequirePkce { get; set; }

    /// <summary>
    /// When true, all UDAP-registered clients will have RequireDPoP set to true,
    /// regardless of the dpop_enabled value in the client's software statement.
    /// Default is false.
    /// </summary>
    public bool ForceDPoP { get; set; }

    /// <summary>
    /// Authorization extension key names required by this server in every token request
    /// (e.g., ["hl7-b2b"]). This is the global default; per-community overrides can be
    /// specified in <see cref="CommunitySettings"/>.
    /// Validated by <see cref="IUdapAuthorizationExtensionValidator"/>.
    /// </summary>
    [JsonPropertyName("AuthorizationExtensionsRequired")]
    public HashSet<string>? AuthorizationExtensionsRequired { get; set; }

    /// <summary>
    /// Allowed purpose_of_use codes (global default).  When set, every code
    /// in the extension's purpose_of_use array must appear in this set.
    /// Null means no restriction.  Per-community overrides in <see cref="CommunitySettings"/>.
    /// </summary>
    [JsonPropertyName("AllowedPurposeOfUse")]
    public HashSet<string>? AllowedPurposeOfUse { get; set; }

    /// <summary>
    /// Maximum number of purpose_of_use entries allowed (global default).
    /// Null means no limit.  TEFCA communities would set this to 1.
    /// Per-community overrides in <see cref="CommunitySettings"/>.
    /// </summary>
    [JsonPropertyName("MaxPurposeOfUseCount")]
    public int? MaxPurposeOfUseCount { get; set; }

    /// <summary>
    /// Per-community overrides for server settings. When a client belongs to a community
    /// that has a matching entry here, the community-specific settings take precedence
    /// over the global defaults.
    /// </summary>
    [JsonPropertyName("CommunitySettings")]
    public List<CommunityServerSettings>? CommunitySettings { get; set; }
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

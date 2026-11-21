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
    /// Accept http redirect URIs on a loopback host (localhost, 127.0.0.1, [::1]) at registration, as native apps
    /// use them (RFC 8252 section 7.3). Off by default: SSRAA requires every redirect URI to use the https scheme.
    /// </summary>
    public bool AllowLoopbackHttpRedirectUris { get; set; }

    /// <summary>
    /// By default the jti claim is required on registration requests.  And replay attacks are monitored.
    /// </summary>
    public bool RegistrationJtiRequired { get; set; } = true;

    /// <summary>
    /// Maximum allowed lifetime, in seconds, of a registration software statement, measured as
    /// <c>exp</c> minus <c>iat</c>. UDAP Dynamic Client Registration section 4.3 recommends a
    /// maximum of 5 minutes, so the default is 300. A software statement whose <c>exp</c> is further
    /// than this from its <c>iat</c> is rejected with <c>invalid_software_statement</c>.
    /// Set to 0 or a negative value to disable the check.
    /// </summary>
    public int SoftwareStatementMaxLifetimeSeconds { get; set; } = 300;

    /// <summary>
    /// Maximum allowed lifetime, in seconds, of a client assertion (Authentication Token) presented
    /// at the token endpoint, measured as <c>exp</c> minus <c>iat</c>. UDAP JWT-Based Client
    /// Authentication section 6.3 recommends a maximum of 5 minutes, so the default is 300.
    /// A client assertion whose <c>exp</c> is further than this from its <c>iat</c> is rejected
    /// with <c>invalid_client</c>. Set to 0 or a negative value to disable the check.
    /// </summary>
    public int ClientAssertionMaxLifetimeSeconds { get; set; } = 300;


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
    /// When true, the community a client belongs to is surfaced in two ways:
    /// at registration the community name (URI) is written to the client's
    /// <c>community</c> property, and at token time a <c>udap_community</c> claim
    /// is added to the access token. The claim value is resolved from the client's
    /// stored community id, so a later community rename is reflected automatically.
    /// Default is false.
    /// </summary>
    public bool IncludeCommunityClaim { get; set; }

    /// <summary>
    /// When true (the default), after a client's authorization extensions have been validated
    /// at the token endpoint, every purpose-of-use code they declare is copied into the access
    /// token as a repeated <c>purpose_of_use</c> claim (one claim per code, value verbatim as
    /// declared), and the <c>hl7-b2b</c> <c>organization_id</c> / <c>organization_name</c> are
    /// copied as claims of the same name. Without this the purpose is validated at issuance and
    /// then discarded, leaving resource servers unable to enforce purpose of use per request or
    /// forward it downstream. Set to false to keep the pre-0.9.7 token shape.
    /// </summary>
    public bool IncludePurposeOfUseClaims { get; set; } = true;

    /// <summary>
    /// Certifications required at registration, per community. Empty by default, so no certification
    /// is required. For a community listed here, a registration is rejected unless its <c>certifications</c>
    /// array holds a valid certification (signature, <c>x5c</c> chain to an anchor of the client's community,
    /// <c>iss</c>/<c>sub</c>, <c>exp</c>) whose <c>certification_uris</c> includes each required URI.
    /// A missing or untrusted certification is rejected with <c>unapproved_software_statement</c>; an invalid
    /// one with <c>invalid_software_statement</c>.
    /// Keep this in step with the <c>udap_certifications_required</c> the resource server advertises.
    ///
    /// <a href="https://www.udap.org/udap-certifications-and-endorsements-stu1.html#section-6">UDAP Certifications and Endorsements section 6</a>
    /// </summary>
    public List<UdapCertificationRequirement> CommunityCertificationsRequired { get; set; } = [];
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

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.IdentityModel.JsonWebTokens;

namespace Udap.Server.Validation;

/// <summary>
/// Context passed to <see cref="IUdapAuthorizationExtensionValidator"/> containing
/// the parsed client assertion and resolved community information.
/// </summary>
public class UdapAuthorizationExtensionValidationContext
{
    /// <summary>
    /// The validated client assertion JWT.
    /// </summary>
    public required JsonWebToken ClientAssertionToken { get; set; }

    /// <summary>
    /// The client_id.
    /// </summary>
    public required string ClientId { get; set; }

    /// <summary>
    /// The deserialized authorization extension objects keyed by extension name
    /// (e.g., "hl7-b2b"). Null if no extensions claim was present in the JWT.
    /// </summary>
    public Dictionary<string, object>? Extensions { get; set; }

    /// <summary>
    /// The community ID the client belongs to (from the client's registered
    /// UDAP_COMMUNITY secret). Null if unknown.
    /// </summary>
    public string? CommunityId { get; set; }

    /// <summary>
    /// The OAuth2 grant type (e.g., "client_credentials", "authorization_code").
    /// Used to resolve grant-type-specific extension requirements.
    /// </summary>
    public string? GrantType { get; set; }

    /// <summary>
    /// The SAN URI the client registered with (from the UDAP_SAN_URI_ISS_NAME secret).
    /// Community validators use this to enforce that the purpose_of_use matches
    /// the exchange purpose embedded in the SAN.
    /// </summary>
    public string? SanUri { get; set; }

    /// <summary>
    /// The community name (URI) the client belongs to.
    /// Used by <see cref="ICommunityTokenValidator"/> implementations to determine applicability.
    /// </summary>
    public string? CommunityName { get; set; }
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Ssraa.Server;

/// <summary>
/// Configuration options for the SSRAA community token validator.
/// Maps community names to the SSRAA validation pipeline.
/// </summary>
public class SsraaValidationOptions
{
    /// <summary>
    /// Community names that should use SSRAA validation rules.
    /// </summary>
    public HashSet<string> Communities { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Extension keys required for client_credentials token requests (e.g., ["hl7-b2b"]).
    /// Default: hl7-b2b required.
    /// </summary>
    public HashSet<string>? ClientCredentialsExtensionsRequired { get; set; } =
        [Udap.Model.UdapConstants.UdapAuthorizationExtensions.Hl7B2B];

    /// <summary>
    /// Extension keys required for authorization_code token requests.
    /// Default: none required.
    /// </summary>
    public HashSet<string>? AuthorizationCodeExtensionsRequired { get; set; }
}

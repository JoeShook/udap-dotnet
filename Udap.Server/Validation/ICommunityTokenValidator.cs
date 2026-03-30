#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Validation;

/// <summary>
/// Community-specific validation of authorization extensions at token time.
/// Implementations are registered as a DI collection and invoked when
/// the client belongs to a matching community.
/// </summary>
public interface ICommunityTokenValidator
{
    /// <summary>
    /// Returns <c>true</c> if this validator should run for the given community.
    /// </summary>
    /// <param name="communityName">
    /// The community URI string (e.g., <c>urn:oid:2.16.840.1.113883.3.7204.1.5</c>).
    /// </param>
    bool AppliesToCommunity(string communityName);

    /// <summary>
    /// Returns the validation rules this validator enforces for the given grant type,
    /// or <c>null</c> to defer to global <c>ServerSettings</c> configuration.
    /// When non-null, these rules override global settings for the matched community.
    /// </summary>
    CommunityValidationRules? GetValidationRules(string? grantType) => null;

    /// <summary>
    /// Validates community-specific token-time rules.
    /// </summary>
    Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context);
}

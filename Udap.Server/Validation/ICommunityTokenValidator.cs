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
///
/// Runs after default extension validation (required keys, allowed
/// purpose_of_use codes, max count) completes successfully.
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
    /// Validates community-specific token-time rules.
    /// </summary>
    Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context);
}

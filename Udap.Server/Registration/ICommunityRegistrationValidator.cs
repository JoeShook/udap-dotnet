#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Registration;

/// <summary>
/// Validates a UDAP registration request for a specific community.
/// Implementations are registered as a DI collection
/// (following the same pattern as <c>IAuthorizationExtensionDeserializer</c>)
/// and invoked for each registration whose resolved community matches.
///
/// Called after core UDAP validation succeeds (JWT, chain, scopes)
/// but before the processor persists the client.
/// </summary>
public interface ICommunityRegistrationValidator
{
    /// <summary>
    /// Returns <c>true</c> if this validator should run for the given community.
    /// </summary>
    /// <param name="communityName">
    /// The community URI string (e.g., <c>urn:oid:2.16.840.1.113883.3.7204.1.5</c>).
    /// </param>
    bool AppliesToCommunity(string communityName);

    /// <summary>
    /// Validates community-specific rules on the registration context.
    /// </summary>
    /// <returns>
    /// <c>null</c> if validation passes; a populated
    /// <see cref="UdapDynamicClientRegistrationValidationResult"/> with an error if rejected.
    /// </returns>
    Task<UdapDynamicClientRegistrationValidationResult?> ValidateAsync(
        UdapDynamicClientRegistrationContext context);
}

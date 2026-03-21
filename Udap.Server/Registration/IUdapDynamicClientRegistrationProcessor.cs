#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Registration;

/// <summary>
/// Processes a validated UDAP Dynamic Client Registration request.
/// Creates the Duende Client model and persists it to the store.
/// Inspired by Duende's DynamicClientRegistrationRequestProcessor pattern.
/// </summary>
public interface IUdapDynamicClientRegistrationProcessor
{
    /// <summary>
    /// Creates a <see cref="Duende.IdentityServer.Models.Client"/> from the validated context
    /// and persists it to the registration store.
    /// </summary>
    /// <param name="context">The context populated by the validator.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A result indicating success or failure.</returns>
    Task<UdapDynamicClientRegistrationProcessorResult> ProcessAsync(
        UdapDynamicClientRegistrationContext context,
        CancellationToken cancellationToken = default);
}

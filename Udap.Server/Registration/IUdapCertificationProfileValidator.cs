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
/// Profile-specific rules for one certification program, identified by its certification URI.
/// Implementations are registered as a DI collection. <see cref="UdapCertificationsRequiredValidator"/>
/// calls <see cref="ValidateAsync"/> after the certification passed the generic UDAP checks
/// (signature, trust chain, <c>iss</c>/<c>sub</c>, <c>exp</c>, <c>certification_uris</c>),
/// and only for communities where <see cref="AppliesToCommunity"/> returns <c>true</c>.
/// </summary>
public interface IUdapCertificationProfileValidator
{
    /// <summary>
    /// The certification URI this validator handles.
    /// </summary>
    string CertificationUri { get; }

    /// <summary>
    /// Returns <c>true</c> if this validator's rules apply to registrations in <paramref name="communityName"/>.
    /// In a community where it returns <c>false</c>, a required certification with <see cref="CertificationUri"/>
    /// still gets the generic checks, but not this validator's profile rules.
    /// </summary>
    bool AppliesToCommunity(string communityName);

    /// <summary>
    /// Returns <c>true</c> if registrations in <paramref name="communityName"/> must carry this certification,
    /// in addition to any community requirement configured in
    /// <see cref="Configuration.ServerSettings.CommunityCertificationsRequired"/>.
    /// </summary>
    bool IsRequiredForCommunity(string communityName);

    /// <summary>
    /// Validates the profile-specific content of a certification that already passed the generic checks.
    /// </summary>
    /// <returns>
    /// <c>null</c> if validation passes; a populated
    /// <see cref="UdapDynamicClientRegistrationValidationResult"/> with an error if rejected.
    /// </returns>
    Task<UdapDynamicClientRegistrationValidationResult?> ValidateAsync(
        UdapDynamicClientRegistrationContext context,
        UdapValidatedCertification certification);
}

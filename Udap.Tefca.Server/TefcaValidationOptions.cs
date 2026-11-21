#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Tefca.Server;

/// <summary>
/// Configuration options for TEFCA community validators.
/// Maps community names to the TEFCA validation pipeline,
/// allowing the same validators to apply to multiple communities
/// regardless of their naming convention.
/// </summary>
public class TefcaValidationOptions
{
    /// <summary>
    /// Community names that should use TEFCA validation rules.
    /// Defaults to <see cref="Udap.Tefca.Model.TefcaConstants.CommunityUri"/>.
    /// </summary>
    public HashSet<string> Communities { get; set; } = new(StringComparer.Ordinal)
    {
        Udap.Tefca.Model.TefcaConstants.CommunityUri
    };

    /// <summary>
    /// When true, token requests for the Treatment exchange purposes (T-TREAT, T-TRTMNT)
    /// must include the provider's NPI and/or TIN appended to <c>organization_name</c> and an
    /// <c>organization_id</c> referencing the RCE Directory Organization entry, per the
    /// Treatment XP Implementation SOP v2.0 Section 6.2. Off by default because the SOP does
    /// not prescribe an exact format for the appended identifiers.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Treatment-XP-SOP-v2.0_7.1.2026_508.pdf#page=8">Treatment XP SOP v2.0 — Section 6.2</a>
    /// </summary>
    public bool EnforceTreatmentOrganizationIdentifiers { get; set; }

    /// <summary>
    /// When true (the default), registration requests and token requests that carry a
    /// <c>user/</c> scope are rejected with <c>invalid_scope</c> instead of being silently
    /// corrected. TEFCA's B2B (<c>client_credentials</c>) and IAS (<c>patient/</c>) flows do
    /// not use <c>user/</c> scopes, and the Facilitated FHIR SOP v2.0 Section 6.11
    /// (Registration #10) requires <c>invalid_scope</c> when a client asks for user scopes
    /// without a user.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf">SOP: Facilitated FHIR Implementation v2.0 — Section 6.11</a>
    /// </summary>
    public bool RejectUserScopes { get; set; } = true;
}

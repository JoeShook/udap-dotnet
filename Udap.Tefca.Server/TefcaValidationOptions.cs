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
    /// Where the exchange purpose code is read from in the client certificate's SAN URI, for both
    /// registration and token validation. Defaults to <see cref="Server.ExchangePurposeLocation.Fragment"/>
    /// (e.g. <c>urn:oid:2.999#T-TRTMNT</c>). SOP v2.0 Section 6.11 (Registration #5a) places the
    /// exchange purpose in the SAN URI path; select <see cref="Server.ExchangePurposeLocation.PathSegment"/>
    /// or <see cref="Server.ExchangePurposeLocation.QueryParameter"/> once the community's SAN format is settled.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">SOP v2.0 — Section 6.11 Registration #5a</a>
    /// </summary>
    public ExchangePurposeLocation ExchangePurposeLocation { get; set; } = ExchangePurposeLocation.Fragment;

    /// <summary>
    /// The query parameter that carries the exchange purpose code when
    /// <see cref="ExchangePurposeLocation"/> is <see cref="Server.ExchangePurposeLocation.QueryParameter"/>.
    /// There is no default: the TEFCA client SAN format is not settled, so the deployment must
    /// configure the name, and startup fails options validation when it is missing.
    /// The name is matched exactly (ordinal, case-sensitive) against the raw SAN text, and the value
    /// is taken verbatim (no percent-decoding), per HL7 SSRAA 3.0.0 "Normalization of URI values in JWTs".
    /// </summary>
    public string? ExchangePurposeQueryParameter { get; set; }
}

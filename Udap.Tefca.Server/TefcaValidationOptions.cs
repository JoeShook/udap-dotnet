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
    /// Optional certificate policy binding, keyed by community name. When a community has an entry,
    /// the client certificate (<c>x5c[0]</c> of the software statement at registration, and of the
    /// client assertion at the token endpoint) must carry at least one subject
    /// <c>organizationalUnitName</c> equal to one of the listed values. Communities without an entry,
    /// or with an empty set, are not checked. Empty by default.
    ///
    /// Production TEFCA communities typically list <see cref="Udap.Tefca.Model.TefcaConstants.OrganizationalUnits.Production"/>
    /// (<c>RCE-FHIR</c>); validation environments list
    /// <see cref="Udap.Tefca.Model.TefcaConstants.OrganizationalUnits.Validation"/> (<c>RCE-FHIR-TEST</c>).
    /// The same CAs issue other certificates that chain to the same anchors; the OU is what binds a
    /// certificate to TEFCA Facilitated FHIR (DirectTrust Certificate Profiles v2.1, Worksheet 4-4).
    /// </summary>
    /// <example>
    /// <code>
    /// options.RequiredCertificateOrganizationalUnits[TefcaConstants.CommunityUri] =
    ///     [TefcaConstants.OrganizationalUnits.Production];
    /// </code>
    /// </example>
    public Dictionary<string, HashSet<string>> RequiredCertificateOrganizationalUnits { get; set; } =
        new(StringComparer.Ordinal);

    /// <summary>
    /// The organizational units a certificate must carry (one is enough) for <paramref name="communityName"/>,
    /// or <c>null</c> when the community has no OU policy.
    /// </summary>
    internal IReadOnlyCollection<string>? GetRequiredOrganizationalUnits(string? communityName)
    {
        if (communityName == null
            || !RequiredCertificateOrganizationalUnits.TryGetValue(communityName, out var units)
            || units.Count == 0)
        {
            return null;
        }

        return units;
    }
}

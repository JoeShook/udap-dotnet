#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Configuration;

/// <summary>
/// The certifications a trust community requires at registration. The server-side counterpart of the
/// <c>udap_certifications_required</c> metadata a resource server advertises for that community.
///
/// <a href="https://www.udap.org/udap-certifications-and-endorsements-stu1.html">UDAP Certifications and Endorsements</a>
/// </summary>
public class UdapCertificationRequirement
{
    /// <summary>
    /// The community name (URI), as resolved from the client certificate's trust anchor,
    /// e.g. <c>udap://fhirlabs.net</c> or <c>urn:oid:2.16.840.1.113883.3.7204.1.5</c>.
    /// </summary>
    public string Community { get; set; } = string.Empty;

    /// <summary>
    /// Certification URIs required for this community. A registration must include, in its
    /// <c>certifications</c> array, a valid certification listing each of these URIs in <c>certification_uris</c>.
    /// </summary>
    public HashSet<string> CertificationUris { get; set; } = new(StringComparer.Ordinal);
}

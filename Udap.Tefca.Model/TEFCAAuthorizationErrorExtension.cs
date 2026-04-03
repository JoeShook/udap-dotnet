#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Udap.Tefca.Model;

/// <summary>
/// TEFCA Authorization Extension Error Object returned in the "extensions" object
/// of an invalid_grant error response when the data holder determines that the
/// authorization metadata submitted is insufficient because the requestor has
/// omitted the ACP parameter or has asserted a policy that is not acceptable.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 B2B #3, Table 1</a>
/// </summary>
public class TEFCAAuthorizationErrorExtension
{
    /// <summary>
    /// consent_required (required):
    /// The list of acceptable Access Consent Policy Identifier(s)
    /// corresponding to the asserted Access Policy required for
    /// authorization, an array of string values from the list of valid policy
    /// OIDs each expressed as a URI.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP v2.0 — Table 1</a>
    /// </summary>
    [JsonPropertyName("consent_required")]
    public ICollection<string> ConsentRequired { get; set; } = [];

    /// <summary>
    /// consent_form (optional):
    /// A URL as a string where the required consent form may be
    /// downloaded, if applicable.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP v2.0 — Table 1</a>
    /// </summary>
    [JsonPropertyName("consent_form")]
    public string? ConsentForm { get; set; }
}

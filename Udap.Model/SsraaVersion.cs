#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Model;

/// <summary>
/// Specifies which version of the HL7 FHIR Implementation Guide "UDAP Security" (SSRAA)
/// the server enforces. The underlying UDAP base protocol (udap.org) remains at version 1
/// in both IG versions; this setting governs server-side enforcement policy only.
/// </summary>
public enum SsraaVersion
{
    /// <summary>
    /// SSRAA IG STU 1.1 — PKCE and the state parameter are optional for
    /// authorization code flows.
    /// </summary>
    V1_1 = 1,

    /// <summary>
    /// SSRAA IG STU 2.0 — PKCE with S256 and the state parameter are required
    /// for all authorization code flows.
    /// </summary>
    V2_0 = 2
}

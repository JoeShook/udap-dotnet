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
/// a server or client enforces. The underlying UDAP base protocol (udap.org) remains at version 1
/// in every IG version; this setting governs enforcement policy only.
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
    V2_0 = 2,

    /// <summary>
    /// SSRAA IG 3.0.0 (package <c>hl7.fhir.uv.fast-security</c>) — everything V2_0 requires, plus the
    /// "Normalization of URI values in JWTs" general requirements: a FHIR base URL has no trailing slash.
    /// Under V2_0 and V3_0 URI values in JWTs (<c>iss</c>, <c>sub</c>, <c>aud</c>) are compared with the
    /// expected value as exact, case-sensitive strings with no normalization.
    /// </summary>
    V3_0 = 3
}

/// <summary>
/// Policy helpers for <see cref="SsraaVersion"/>.
/// </summary>
public static class SsraaVersionExtensions
{
    /// <summary>
    /// True when the version requires PKCE (S256) and the state parameter for authorization code flows
    /// (V2_0 and later).
    /// </summary>
    public static bool RequiresPkceAndState(this SsraaVersion version) => version >= SsraaVersion.V2_0;

    /// <summary>
    /// True when URI values in JWTs must be compared as exact, case-sensitive strings with no normalization
    /// (V2_0 and later). V1_1 keeps the lenient comparison (case-insensitive, trailing slash ignored).
    /// </summary>
    public static bool RequiresExactUriComparison(this SsraaVersion version) => version >= SsraaVersion.V2_0;

    /// <summary>
    /// True when a FHIR base URL must not end in a slash (V3_0 and later).
    /// </summary>
    public static bool ForbidsBaseUrlTrailingSlash(this SsraaVersion version) => version >= SsraaVersion.V3_0;
}

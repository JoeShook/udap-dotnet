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
/// Where the TEFCA Exchange Purpose (XP) code is carried in a client certificate's SAN URI.
/// </summary>
public enum ExchangePurposeLocation
{
    /// <summary>
    /// The URI fragment, e.g. <c>urn:oid:2.999#T-TRTMNT</c>. This is the default.
    /// </summary>
    Fragment = 0,

    /// <summary>
    /// A path segment that is a valid exchange purpose code,
    /// e.g. <c>https://example.com/fhir/T-TRTMNT</c>.
    /// </summary>
    PathSegment = 1,

    /// <summary>
    /// A named query parameter (see <see cref="TefcaValidationOptions.ExchangePurposeQueryParameter"/>,
    /// which has no default and must be configured), e.g.
    /// <c>https://example.com/fhir?&lt;your-parameter-name&gt;=T-TRTMNT</c>.
    /// </summary>
    QueryParameter = 2
}

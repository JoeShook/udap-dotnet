#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Validation;

/// <summary>
/// Community-specific rule for the <c>x5c</c> header of software statements and client assertions.
/// Implementations are registered as a DI collection. Communities no implementation claims keep the base
/// UDAP behaviour: the client may send only its certificate and the server completes the chain from its
/// configured intermediates and Authority Information Access (AIA) URLs.
/// </summary>
public interface ICommunityX5cPolicy
{
    /// <summary>
    /// Returns <c>true</c> when the community requires the <c>x5c</c> header to carry the client certificate
    /// followed by the intermediate that issued it. For such a community the server builds the chain from the
    /// intermediates in <c>x5c</c> and the intermediates it has configured, never downloads an intermediate
    /// from an AIA URL, and rejects a JWT whose <c>x5c</c> lacks the issuing intermediate.
    /// </summary>
    /// <param name="communityName">The community URI string.</param>
    bool RequiresIssuingIntermediateInX5c(string communityName);
}

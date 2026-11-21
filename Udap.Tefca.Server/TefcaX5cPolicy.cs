#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;
using Udap.Server.Validation;

namespace Udap.Tefca.Server;

/// <summary>
/// TEFCA communities require the <c>x5c</c> header to carry the client certificate followed by the
/// intermediate that issued it. See <see cref="TefcaValidationOptions.RequireIssuingIntermediateInX5c"/>.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf">
/// SOP: Facilitated FHIR Implementation v2.0 — Section 6.1</a>
/// </summary>
public class TefcaX5cPolicy : ICommunityX5cPolicy
{
    private readonly IOptionsMonitor<TefcaValidationOptions> _options;

    public TefcaX5cPolicy(IOptionsMonitor<TefcaValidationOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc />
    public bool RequiresIssuingIntermediateInX5c(string communityName)
    {
        var options = _options.CurrentValue;

        return options.RequireIssuingIntermediateInX5c && options.Communities.Contains(communityName);
    }
}

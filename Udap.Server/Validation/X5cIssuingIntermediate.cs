#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Certificates;
using Udap.Model.Statement;

namespace Udap.Server.Validation;

/// <summary>
/// Checks that a JWT <c>x5c</c> header carries the signing certificate followed by the intermediate that issued it.
/// Used when <see cref="Configuration.ServerSettings.RequireIssuingIntermediateInX5c"/> is set.
/// </summary>
internal static class X5cIssuingIntermediate
{
    /// <summary>
    /// Returns true when the second <c>x5c</c> entry is the issuer of the signing certificate in the validated
    /// chain, or when that issuer is a self-signed trust anchor and so there is no intermediate to include.
    /// </summary>
    /// <param name="x5c">The base64 DER certificates of the <c>x5c</c> header, signing certificate first.</param>
    /// <param name="chainValidationResult">A successful chain validation of the first <c>x5c</c> certificate.</param>
    internal static bool IsPresent(IReadOnlyList<string>? x5c, ChainValidationResult chainValidationResult)
    {
        var chain = chainValidationResult.ChainElements;

        if (chain.Count < 2)
        {
            return true;
        }

        var issuer = chain[1].Certificate;

        if (X5cChain.IsSelfSigned(issuer))
        {
            return true;
        }

        if (x5c == null || x5c.Count < 2)
        {
            return false;
        }

        byte[] presented;

        try
        {
            presented = Convert.FromBase64String(x5c[1]);
        }
        catch (FormatException)
        {
            return false;
        }

        return presented.AsSpan().SequenceEqual(issuer.RawData);
    }
}

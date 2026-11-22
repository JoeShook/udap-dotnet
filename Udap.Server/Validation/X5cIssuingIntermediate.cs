#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Udap.Common.Certificates;
using Udap.Model.Statement;

namespace Udap.Server.Validation;

/// <summary>
/// Checks that a JWT <c>x5c</c> header carries the signing certificate followed by the intermediate that issued it.
/// Used for communities an <see cref="ICommunityX5cPolicy"/> claims.
/// </summary>
internal static class X5cIssuingIntermediate
{
    /// <summary>
    /// Returns true when any registered policy requires the issuing intermediate in x5c for <paramref name="communityName"/>.
    /// </summary>
    internal static bool IsRequired(IEnumerable<ICommunityX5cPolicy> policies, string? communityName)
    {
        return !string.IsNullOrEmpty(communityName) &&
               policies.Any(p => p.RequiresIssuingIntermediateInX5c(communityName));
    }

    /// <summary>
    /// The certificates after the first in an <c>x5c</c> header, for chain building. Entries that are not
    /// valid base64 DER certificates are skipped; chain validation decides whether what remains is enough.
    /// </summary>
    internal static X509Certificate2Collection ReadIntermediates(IReadOnlyList<string>? x5c)
    {
        var intermediates = new X509Certificate2Collection();

        if (x5c == null)
        {
            return intermediates;
        }

        foreach (var entry in x5c.Skip(1))
        {
            try
            {
#if NET9_0_OR_GREATER
                intermediates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(entry)));
#else
                intermediates.Add(new X509Certificate2(Convert.FromBase64String(entry)));
#endif
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                // Skipped: not a certificate.
            }
        }

        return intermediates;
    }

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

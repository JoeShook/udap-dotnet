#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Udap.Model.Statement;

/// <summary>
/// Orders the certificates placed in a JWT <c>x5c</c> header: the signing (leaf) certificate first,
/// followed by the intermediate that issued it, then that intermediate's issuer, and so on.
/// Self-signed (root) certificates are never included; the relying party already holds its trust anchors.
/// </summary>
/// <remarks>
/// Issuers are matched by name (the certificate's issuer equals the candidate's subject) and, when both
/// certificates carry them, by Authority Key Identifier / Subject Key Identifier. This only orders the
/// chain the signer presents; it is not a trust decision. The relying party still validates the chain.
/// </remarks>
public static class X5cChain
{
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string SubjectKeyIdentifierOid = "2.5.29.14";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";

    /// <summary>
    /// Builds the ordered <c>x5c</c> certificate list for <paramref name="signingCertificate"/>:
    /// the signing certificate followed by each issuing intermediate found in <paramref name="intermediates"/>.
    /// Certificates in <paramref name="intermediates"/> that are not part of the signing certificate's chain are ignored.
    /// </summary>
    /// <param name="signingCertificate">The signing (leaf) certificate.</param>
    /// <param name="intermediates">Candidate CA certificates, in any order. May be null or empty.</param>
    /// <returns>The signing certificate followed by its issuing intermediates, nearest issuer first.</returns>
    public static List<X509Certificate2> Build(X509Certificate2 signingCertificate, IEnumerable<X509Certificate2>? intermediates)
    {
        if (signingCertificate == null)
        {
            throw new ArgumentNullException(nameof(signingCertificate));
        }

        var chain = new List<X509Certificate2> { signingCertificate };
        var candidates = intermediates?
            .Where(c => c != null && IsCertificateAuthority(c) && !IsSelfSigned(c))
            .ToList() ?? [];

        var current = signingCertificate;

        while (candidates.Count > 0)
        {
            var issuer = FindIssuer(current, candidates);

            if (issuer == null || chain.Any(c => c.RawData.AsSpan().SequenceEqual(issuer.RawData)))
            {
                break;
            }

            chain.Add(issuer);
            candidates.Remove(issuer);
            current = issuer;
        }

        return chain;
    }

    /// <summary>
    /// Returns true when <paramref name="certificates"/> holds a signing certificate followed by the
    /// intermediate that issued it, i.e. the second certificate is the issuer of the first.
    /// </summary>
    /// <param name="certificates">An ordered <c>x5c</c> certificate list.</param>
    public static bool IncludesIssuingIntermediate(IReadOnlyList<X509Certificate2> certificates)
    {
        if (certificates == null || certificates.Count < 2)
        {
            return false;
        }

        var issuer = certificates[1];

        return IsCertificateAuthority(issuer) && !IsSelfSigned(issuer) && IsIssuedBy(certificates[0], issuer);
    }

    /// <summary>
    /// Finds the certificate in <paramref name="candidates"/> that issued <paramref name="certificate"/>.
    /// </summary>
    /// <param name="certificate">The certificate whose issuer is wanted.</param>
    /// <param name="candidates">Candidate CA certificates.</param>
    /// <returns>The issuing certificate, or null when none of the candidates issued it.</returns>
    public static X509Certificate2? FindIssuer(X509Certificate2 certificate, IEnumerable<X509Certificate2> candidates)
    {
        return candidates.FirstOrDefault(c => IsIssuedBy(certificate, c));
    }

    /// <summary>
    /// Returns true when <paramref name="certificate"/> names <paramref name="issuer"/> as its issuer.
    /// </summary>
    public static bool IsIssuedBy(X509Certificate2 certificate, X509Certificate2 issuer)
    {
        if (!certificate.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData))
        {
            return false;
        }

        var authorityKeyId = GetAuthorityKeyIdentifier(certificate);
        var subjectKeyId = GetSubjectKeyIdentifier(issuer);

        if (authorityKeyId != null && subjectKeyId != null)
        {
            return authorityKeyId.AsSpan().SequenceEqual(subjectKeyId);
        }

        return true;
    }

    /// <summary>
    /// Returns true when the certificate's subject and issuer are the same name (a root certificate).
    /// </summary>
    public static bool IsSelfSigned(X509Certificate2 certificate)
    {
        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }

    /// <summary>
    /// Returns true when the certificate's basic constraints mark it as a certificate authority.
    /// </summary>
    public static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        return certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == BasicConstraintsOid)
            is X509BasicConstraintsExtension { CertificateAuthority: true };
    }

    private static byte[]? GetSubjectKeyIdentifier(X509Certificate2 certificate)
    {
        return certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == SubjectKeyIdentifierOid)
            is X509SubjectKeyIdentifierExtension ski
            ? ski.SubjectKeyIdentifierBytes.ToArray()
            : null;
    }

    private static byte[]? GetAuthorityKeyIdentifier(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == AuthorityKeyIdentifierOid);

        if (extension == null)
        {
            return null;
        }

        var aki = extension as X509AuthorityKeyIdentifierExtension
                  ?? new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical);

        return aki.KeyIdentifier?.ToArray();
    }
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Udap.Common.Models;
using Udap.Model.Statement;

namespace Udap.Common.Certificates;

/// <summary>
/// Creates <see cref="IssuedCertificate"/> instances that carry their issuing intermediate, so JWTs signed
/// with them can send the signing certificate followed by that intermediate in the <c>x5c</c> header.
/// </summary>
internal static class IssuedCertificateFactory
{
    /// <summary>
    /// Loads the CA certificates listed in a community's <c>Intermediates</c> file paths.
    /// </summary>
    internal static List<X509Certificate2> LoadCommunityIntermediates(Metadata.Community community, ILogger logger)
    {
        var intermediates = new List<X509Certificate2>();

        foreach (var intermediateFilePath in community.Intermediates)
        {
            var path = Path.Combine(AppContext.BaseDirectory, intermediateFilePath);

            if (!File.Exists(path))
            {
                logger.LogWarning("Cannot find intermediate file: {FilePath}", path);
                continue;
            }

#if NET9_0_OR_GREATER
            intermediates.Add(X509CertificateLoader.LoadCertificateFromFile(path));
#else
            intermediates.Add(new X509Certificate2(path));
#endif
        }

        return intermediates;
    }

    /// <summary>
    /// Creates an <see cref="IssuedCertificate"/> whose intermediates are taken from the other certificates in
    /// its PKCS#12 file and from the community's configured intermediates. Logs a warning when no issuing
    /// intermediate is available, because the <c>x5c</c> header of JWTs it signs will then carry only the leaf.
    /// </summary>
    internal static IssuedCertificate Create(
        X509Certificate2 certificate,
        string community,
        IEnumerable<X509Certificate2> bundledCertificates,
        IEnumerable<X509Certificate2> communityIntermediates,
        ILogger logger)
    {
        var bundled = bundledCertificates.ToList();
        var issued = new IssuedCertificate(certificate, community, bundled.Concat(communityIntermediates));

        if (issued.Intermediates.Count == 0)
        {
            var issuedByBundledRoot = X5cChain.FindIssuer(certificate, bundled.Where(X5cChain.IsSelfSigned)) != null;

            if (issuedByBundledRoot)
            {
                logger.LogInformation(
                    "Certificate {Thumbprint} ({SubjectName}) is issued directly by a root certificate; the x5c header will carry only this certificate",
                    certificate.Thumbprint, certificate.SubjectName.Name);
            }
            else
            {
                logger.LogWarning(
                    "The intermediate that issued certificate {Thumbprint} ({SubjectName}, issuer {IssuerName}) is not available from the certificate store; " +
                    "the x5c header will carry only this certificate. Add the intermediate to the PKCS#12 file or to the community's Intermediates.",
                    certificate.Thumbprint, certificate.SubjectName.Name, certificate.IssuerName.Name);
            }
        }

        return issued;
    }
}

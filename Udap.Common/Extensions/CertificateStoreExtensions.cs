#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;
using Udap.Util.Extensions;

namespace Udap.Common.Extensions;

/// <summary>
/// Extension methods for converting certificate store models to .NET X.509 types.
/// </summary>
public static class CertificateStoreExtensions
{
    /// <summary>
    /// Converts a collection of <see cref="Anchor"/> models to an <see cref="X509Certificate2Collection"/>
    /// by parsing each anchor's PEM-encoded certificate.
    /// </summary>
    /// <param name="anchors">The anchor certificates to convert.</param>
    /// <returns>An <see cref="X509Certificate2Collection"/> containing the parsed certificates.</returns>
    public static X509Certificate2Collection? ToX509Collection(this IEnumerable<Anchor> anchors)
    {
        return anchors
            .Select(a => X509Certificate2.CreateFromPem(a.Certificate))
            .ToArray()
            .ToX509Collection();
    }
}

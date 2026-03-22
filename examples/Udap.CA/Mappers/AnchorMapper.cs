#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Udap.CA.Entities;

namespace Udap.CA.Mappers;

public static class AnchorMapper
{
    /// <summary>
    /// Maps an entity to a view model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static ViewModel.Anchor ToModel(this Anchor entity)
    {
        return new ViewModel.Anchor
        {
            Id = entity.Id,
            Enabled = entity.Enabled,
            Subject = entity.Subject,
            SubjectAltName = entity.SubjectAltName,
            CertificateRevocation = entity.CertificateRevocation,
            CertificateAuthIssuerUri = entity.CertificateAuthIssuerUri,
            Certificate = !string.IsNullOrEmpty(entity.X509Certificate)
                ? new X509Certificate2(Convert.FromBase64String(
                    entity.X509Certificate
                        .Replace("-----BEGIN CERTIFICATE-----", "")
                        .Replace("-----END CERTIFICATE-----", "")
                        .Trim()))
                : null,
            Thumbprint = entity.Thumbprint,
            BeginDate = entity.BeginDate,
            EndDate = entity.EndDate,
            RootCertificateId = entity.RootCertificateId
        };
    }

    /// <summary>
    /// Maps a view model to an entity.
    /// </summary>
    /// <param name="model">The view model.</param>
    /// <returns></returns>
    public static Anchor ToEntity(this ViewModel.Anchor model)
    {
        return new Anchor
        {
            Id = (int)model.Id,
            Enabled = model.Enabled,
            Subject = model.Subject,
            SubjectAltName = model.SubjectAltName,
            CertificateRevocation = model.CertificateRevocation,
            CertificateAuthIssuerUri = model.CertificateAuthIssuerUri,
            X509Certificate = model.Certificate != null
                ? Convert.ToBase64String(model.Certificate.Export(X509ContentType.Cert))
                : string.Empty,
            Thumbprint = model.Thumbprint ?? string.Empty,
            BeginDate = model.BeginDate ?? DateTime.MinValue,
            EndDate = model.EndDate ?? DateTime.MinValue,
            RootCertificateId = model.RootCertificateId
        };
    }
}

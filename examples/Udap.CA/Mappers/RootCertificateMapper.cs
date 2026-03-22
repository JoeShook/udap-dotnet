#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Udap.CA.Entities;
using Udap.Common;

namespace Udap.CA.Mappers;

public static class RootCertificateMapper
{
    /// <summary>
    /// Maps an entity to a view model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static ViewModel.RootCertificate ToViewModel(this RootCertificate entity)
    {
        return new ViewModel.RootCertificate
        {
            Id = entity.Id,
            CommunityId = entity.CommunityId,
            Enabled = entity.Enabled,
            Name = entity.Name,
            Certificate = X509Certificate2.CreateFromPem(entity.X509Certificate),
            Thumbprint = entity.Thumbprint,
            Url = entity.Url,
            BeginDate = entity.BeginDate,
            EndDate = entity.EndDate
        };
    }

    /// <summary>
    /// Maps a view model to an entity.
    /// </summary>
    /// <param name="model">The view model.</param>
    /// <returns></returns>
    public static RootCertificate ToEntity(this ViewModel.RootCertificate model)
    {
        return new RootCertificate
        {
            Id = model.Id,
            CommunityId = model.CommunityId,
            Enabled = model.Enabled,
            Name = model.Name,
            RSAPrivateKey = model.Certificate != null
                ? PemEncoding.WriteString(
                    PemLabels.RsaPrivateKey,
                    model.Certificate.Export(X509ContentType.Pkcs12, model.Secret))
                : string.Empty,
            X509Certificate = model.Certificate != null
                ? PemEncoding.WriteString(
                    PemLabels.X509Certificate,
                    model.Certificate.Export(X509ContentType.Cert))
                : string.Empty,
            Thumbprint = model.Thumbprint ?? string.Empty,
            Url = model.Url,
            BeginDate = model.BeginDate ?? DateTime.Now,
            EndDate = model.EndDate ?? DateTime.Now.AddYears(10)
        };
    }

    /// <summary>
    /// Maps a collection of entities to a collection of view models.
    /// </summary>
    public static ICollection<ViewModel.RootCertificate> ToViewModels(this IEnumerable<RootCertificate> entities)
    {
        return entities.Select(e => e.ToViewModel()).ToList();
    }
}

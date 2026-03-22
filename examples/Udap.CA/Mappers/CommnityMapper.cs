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

namespace Udap.CA.Mappers
{
    public static class CommunityMapper
    {
        /// <summary>
        /// Maps an entity to a view model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static ViewModel.Community ToViewModel(this Community entity)
        {
            return new ViewModel.Community
            {
                Id = entity.Id,
                Name = entity.Name,
                Enabled = entity.Enabled,
                RootCertificates = entity.RootCertificates?.Select(rc => new ViewModel.RootCertificate
                {
                    Id = rc.Id,
                    CommunityId = rc.CommunityId,
                    Name = rc.Name,
                    Url = rc.Url,
                    Thumbprint = rc.Thumbprint,
                    BeginDate = rc.BeginDate,
                    EndDate = rc.EndDate,
                    Enabled = rc.Enabled,
                    Certificate = X509Certificate2.CreateFromPem(rc.X509Certificate),
                }).ToHashSet() ?? new HashSet<ViewModel.RootCertificate>()
            };
        }

        /// <summary>
        /// Maps a view model to an entity.
        /// </summary>
        /// <param name="model">The view model.</param>
        /// <returns></returns>
        public static Community ToEntity(this ViewModel.Community model)
        {
            return new Community(model.Name, model.Enabled)
            {
                Id = model.Id
            };
        }

        /// <summary>
        /// Maps a collection of entities to a collection of view models.
        /// </summary>
        public static ICollection<ViewModel.Community> ToViewModels(this IEnumerable<Community> entities)
        {
            return entities.Select(e => e.ToViewModel()).ToList();
        }
    }
}

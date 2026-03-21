#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Server.Storage.Entities;

namespace Udap.Server.Storage.Mappers
{
    public static class CommunityMapper
    {
        /// <summary>
        /// Maps an entity to a model.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <returns></returns>
        public static Common.Models.Community ToModel(this Community entity)
        {
            return new Common.Models.Community
            {
                Id = entity.Id,
                Name = entity.Name,
                Enabled = entity.Enabled,
                Default = entity.Default,
                Anchors = entity.Anchors?.Select(a => a.ToModel()).ToList(),
                Certifications = entity.Certifications?.Select(c => new Common.Models.Certification
                {
                    Id = c.Id,
                    Name = c.Name
                }).ToList()
            };
        }

        /// <summary>
        /// Maps a model to an entity.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns></returns>
        public static Community ToEntity(this Common.Models.Community model)
        {
            return new Community
            {
                Id = model.Id,
                Name = model.Name,
                Enabled = model.Enabled,
                Default = model.Default,
                Anchors = model.Anchors?.Select(a => a.ToEntity()).ToList(),
                Certifications = model.Certifications?.Select(c => new Certification
                {
                    Id = (int)c.Id,
                    Name = c.Name
                }).ToList()
            };
        }
    }
}

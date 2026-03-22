#region (c) 2023-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Server.Storage.Entities;

namespace Udap.Server.Storage.Mappers;

public static class TieredClientMapper
{
    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Common.Models.TieredClient ToModel(this TieredClient? entity)
    {
        if (entity == null)
        {
            return new Common.Models.TieredClient();
        }

        return new Common.Models.TieredClient
        {
            Id = entity.Id,
            ClientName = entity.ClientName,
            ClientId = entity.ClientId,
            IdPBaseUrl = entity.IdPBaseUrl,
            RedirectUri = entity.RedirectUri,
            ClientUriSan = entity.ClientUriSan,
            CommunityId = entity.CommunityId,
            Enabled = entity.Enabled,
            TokenEndpoint = entity.TokenEndpoint
        };
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static TieredClient ToEntity(this Common.Models.TieredClient model)
    {
        return new TieredClient
        {
            Id = model.Id,
            ClientName = model.ClientName ?? string.Empty,
            ClientId = model.ClientId ?? string.Empty,
            IdPBaseUrl = model.IdPBaseUrl ?? string.Empty,
            RedirectUri = model.RedirectUri ?? string.Empty,
            ClientUriSan = model.ClientUriSan ?? string.Empty,
            CommunityId = model.CommunityId,
            Enabled = model.Enabled,
            TokenEndpoint = model.TokenEndpoint ?? string.Empty
        };
    }
}

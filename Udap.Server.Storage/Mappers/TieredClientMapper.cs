#region (c) 2023-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using AutoMapper;
using Udap.Server.Storage.Entities;

namespace Udap.Server.Storage.Mappers;

public static class TieredClientMapper
{
    static TieredClientMapper()
    {
        Mapper = new MapperConfiguration(cfg =>
        {
            cfg.AddProfile<TieredClientMapperProfile>();
        })
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Common.Models.TieredClient ToModel(this TieredClient? entity)
    {
        return Mapper.Map<Common.Models.TieredClient>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static TieredClient ToEntity(this Common.Models.TieredClient model)
    {
        return Mapper.Map<TieredClient>(model);
    }
}

public class TieredClientMapperProfile : Profile
{
    public TieredClientMapperProfile()
    {
        CreateMap<TieredClient, Common.Models.TieredClient>(MemberList.Destination)
            .ConstructUsing(src => new Common.Models.TieredClient())
            .ReverseMap()
            ;
    }
}
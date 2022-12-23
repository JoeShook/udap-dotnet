#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

//
// Modified to add a UdapClientSecrets table with a larger value column
//

using System.Security.Claims;
using AutoMapper;
using Udap.Server.Entities;

namespace Udap.Server.Mappers;

/// <summary>
/// Extension methods to map to/from entity/model for clients.
/// </summary>
public static class ClientMappers
{
    static ClientMappers()
    {
        Mapper = new MapperConfiguration(cfg => cfg.AddProfile<UdapClientMapperProfile>())
            .CreateMapper();
    }

    internal static IMapper Mapper { get; }

    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns></returns>
    public static Duende.IdentityServer.Models.Client ToModel(this UdapClient entity)
    {
        return Mapper.Map<Duende.IdentityServer.Models.Client>(entity);
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns></returns>
    public static UdapClient ToEntity(this Duende.IdentityServer.Models.Client model)
    {
        return Mapper.Map<UdapClient>(model);
    }
}


/// <summary>
/// Defines entity/model mapping for clients.
/// </summary>
/// <seealso cref="AutoMapper.Profile" />
public class UdapClientMapperProfile : Profile
{
    /// <summary>
    ///     <see cref="UdapClientMapperProfile"/>
    /// Modification Duende ClientMapperProfile with the addition of mapping UdapClientSecrets
    /// </summary>
    public UdapClientMapperProfile()
    {
        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientProperty, KeyValuePair<string, string>>()
            .ReverseMap();

        CreateMap<UdapClient, Duende.IdentityServer.Models.Client>()
            .ForMember(dest => dest.ProtocolType, opt => opt.Condition(srs => srs != null))
            .ForMember(x => x.AllowedIdentityTokenSigningAlgorithms, opts => opts.ConvertUsing(AllowedSigningAlgorithmsConverter.Converter, x => x.AllowedIdentityTokenSigningAlgorithms))
            .ReverseMap()
            .ForMember(x => x.AllowedIdentityTokenSigningAlgorithms, opts => opts.ConvertUsing(AllowedSigningAlgorithmsConverter.Converter, x => x.AllowedIdentityTokenSigningAlgorithms));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientCorsOrigin, string>()
            .ConstructUsing(src => src.Origin)
            .ReverseMap()
            .ForMember(dest => dest.Origin, opt => opt.MapFrom(src => src));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientIdPRestriction, string>()
            .ConstructUsing(src => src.Provider)
            .ReverseMap()
            .ForMember(dest => dest.Provider, opt => opt.MapFrom(src => src));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientClaim, Duende.IdentityServer.Models.ClientClaim>(MemberList.None)
            .ConstructUsing(src => new Duende.IdentityServer.Models.ClientClaim(src.Type, src.Value, ClaimValueTypes.String))
            .ReverseMap();

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientScope, string>()
            .ConstructUsing(src => src.Scope)
            .ReverseMap()
            .ForMember(dest => dest.Scope, opt => opt.MapFrom(src => src));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientPostLogoutRedirectUri, string>()
            .ConstructUsing(src => src.PostLogoutRedirectUri)
            .ReverseMap()
            .ForMember(dest => dest.PostLogoutRedirectUri, opt => opt.MapFrom(src => src));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientRedirectUri, string>()
            .ConstructUsing(src => src.RedirectUri)
            .ReverseMap()
            .ForMember(dest => dest.RedirectUri, opt => opt.MapFrom(src => src));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientGrantType, string>()
            .ConstructUsing(src => src.GrantType)
            .ReverseMap()
            .ForMember(dest => dest.GrantType, opt => opt.MapFrom(src => src));

        CreateMap<Duende.IdentityServer.EntityFramework.Entities.ClientSecret, Duende.IdentityServer.Models.Secret>(MemberList.Destination)
            .ForMember(dest => dest.Type, opt => opt.Condition(srs => 
                srs != null &&
                srs.Type != UdapServerConstants.SecretTypes.Udapx5c))
            .ReverseMap();
        
        CreateMap<UdapClientSecrets, Duende.IdentityServer.Models.Secret>(MemberList.Destination)
            .ForMember(dest => dest.Type, opt => opt.Condition(srs => 
                srs != null && 
                srs.Type == UdapServerConstants.SecretTypes.Udapx5c))
            .ReverseMap();
    }
}
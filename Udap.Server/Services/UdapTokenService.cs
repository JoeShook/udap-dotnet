#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Udap.Common;

namespace Udap.Server.Services;
public class UdapTokenService : DefaultTokenService
{
    /// <summary>
    /// Initializes and override new instance of the <see cref="T:Duende.IdentityServer.Services.DefaultTokenService" /> class.
    /// </summary>
    /// <param name="claimsProvider">The claims provider.</param>
    /// <param name="referenceTokenStore">The reference token store.</param>
    /// <param name="creationService">The signing service.</param>
    /// <param name="contextAccessor">The HTTP context accessor.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="keyMaterialService"></param>
    /// <param name="options">The IdentityServer options</param>
    /// <param name="logger">The logger.</param>
    public UdapTokenService(IClaimsService claimsProvider, IReferenceTokenStore referenceTokenStore, ITokenCreationService creationService, IHttpContextAccessor contextAccessor, ISystemClock clock, IKeyMaterialService keyMaterialService, IdentityServerOptions options, ILogger<DefaultTokenService> logger) : base(claimsProvider, referenceTokenStore, creationService, contextAccessor, clock, keyMaterialService, options, logger)
    {
    }

    /// <summary>Creates a serialized and protected security token.</summary>
    /// <param name="token">The token.</param>
    /// <returns>A security token in serialized form</returns>
    /// <exception cref="T:System.InvalidOperationException">Invalid token type.</exception>
    public override async Task<string> CreateSecurityTokenAsync(Token token)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("UdapTokenService.CreateSecurityToken");

        string tokenResult;

        if (token.Type == OidcConstants.TokenTypes.AccessToken)
        {
            var currentJwtId = token.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.JwtId);
            if (token.IncludeJwtId || (currentJwtId != null && token.Version < 5))
            {
                if (currentJwtId != null)
                {
                    token.Claims.Remove(currentJwtId);
                }
                token.Claims.Add(new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex)));
            }

            if (token.AccessTokenType == AccessTokenType.Jwt)
            {
                Logger.LogTrace("Creating JWT access token");

                tokenResult = await CreationService.CreateTokenAsync(token);
            }
            else
            {
                Logger.LogTrace("Creating reference access token");

                var handle = await ReferenceTokenStore.StoreReferenceTokenAsync(token);

                tokenResult = handle;
            }
        }
        else if (token.Type == OidcConstants.TokenTypes.IdentityToken)
        {
            Logger.LogTrace("Creating JWT identity token");

            tokenResult = await CreationService.CreateTokenAsync(token);
        }
        else
        {
            throw new InvalidOperationException("Invalid token type.");
        }

        return tokenResult;
    }
}

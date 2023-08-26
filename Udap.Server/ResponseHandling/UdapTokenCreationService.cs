#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Udap.Common;
using Udap.Common.Extensions;

namespace Udap.Server.ResponseHandling;

/// <summary>
/// UDAP token creation service
/// Generates tokens correlated to algorithm and key id.  The key id maps to a trust community's PKI.
/// </summary>
public class UdapTokenCreationService : ITokenCreationService
{
    /// <summary>
    /// The key service
    /// </summary>
    protected readonly IKeyMaterialService Keys;

    /// <summary>
    /// The logger
    /// </summary>
    protected readonly ILogger Logger;

    /// <summary>
    ///  The clock
    /// </summary>
    protected readonly ISystemClock Clock;

    /// <summary>
    /// The options
    /// </summary>
    protected readonly IdentityServerOptions Options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultTokenCreationService"/> class.
    /// </summary>
    /// <param name="clock">The options.</param>
    /// <param name="keys">The keys.</param>
    /// <param name="options">The options.</param>
    /// <param name="logger">The logger.</param>
    public UdapTokenCreationService(
        ISystemClock clock,
        IKeyMaterialService keys,
        IdentityServerOptions options,
        ILogger<DefaultTokenCreationService> logger)
    {
        Clock = clock;
        Keys = keys;
        Options = options;
        Logger = logger;
    }


    /// <summary>Creates a token.</summary>
    /// <param name="token">The token description.</param>
    /// <returns>A protected and serialized security token</returns>
    public async Task<string> CreateTokenAsync(Token token)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("UdapTokenCreationService.CreateToken");

        var payload = await CreatePayloadAsync(token);
        var headerElements = await CreateHeaderElementsAsync(token);

        return await CreateJwtAsync(token, payload, headerElements);
    }

    /// <summary>
    /// Creates the JWT payload
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    protected virtual Task<string> CreatePayloadAsync(Token token)
    {
        var payload = token.CreateJwtPayloadDictionary(Options, Clock, Logger);
        return Task.FromResult(JsonSerializer.Serialize(payload));
    }

    /// <summary>
    /// Creates additional JWT header elements
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    protected virtual Task<Dictionary<string, object>> CreateHeaderElementsAsync(Token token)
    {
        var additionalHeaderElements = new Dictionary<string, object>();

        if (token.Type == IdentityServerConstants.TokenTypes.AccessToken)
        {
            if (Options.AccessTokenJwtType.IsPresent())
            {
                additionalHeaderElements.Add("typ", Options.AccessTokenJwtType);
            }
        }
        else if (token.Type == IdentityServerConstants.TokenTypes.LogoutToken)
        {
            if (Options.LogoutTokenJwtType.IsPresent())
            {
                additionalHeaderElements.Add("typ", Options.LogoutTokenJwtType);
            }
        }

        return Task.FromResult(additionalHeaderElements);
    }

    /// <summary>
    /// Creates JWT token
    /// </summary>
    /// <param name="token"></param>
    /// <param name="payload"></param>
    /// <param name="headerElements"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    protected virtual async Task<string> CreateJwtAsync(Token token, string payload,
        Dictionary<string, object> headerElements)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("UdapTokenCreationService.CreateJwt");

        var credential = await Keys.GetSigningCredentialsAsync(token.AllowedSigningAlgorithms);

        if (credential == null)
        {
            throw new InvalidOperationException("No signing credential is configured. Can't create JWT token");
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(payload, credential, headerElements);
    }
}

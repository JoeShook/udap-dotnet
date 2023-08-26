#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services.KeyManagement;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Server.KeyManagement;


/// <summary>
/// Implementation of IValidationKeysStore and ISigningCredentialStore based on UDAP client certificates issued by multiple PKIs.
/// </summary>
public class UdapAutomaticKeyManagerStore : IAutomaticKeyManagerKeyStore
{
    private readonly IKeyManager _keyManager;
    private readonly KeyManagementOptions _options;

    /// <summary>
    /// Constructor for KeyManagerKeyStore.
    /// </summary>
    /// <param name="keyManager"></param>
    /// <param name="options"></param>
    public UdapAutomaticKeyManagerStore(IKeyManager keyManager, KeyManagementOptions options)
    {
        _keyManager = keyManager;
        _options = options;
    }


    /// <summary>Gets the signing credentials.</summary>
    /// <returns></returns>
    public async Task<SigningCredentials?> GetSigningCredentialsAsync()
    {
        if (!_options.Enabled)
        {
            return null;
        }

        var credentials = await GetAllSigningCredentialsAsync();
        var alg = _options.SigningAlgorithms.First().Name;
        var credential = credentials.FirstOrDefault(x => alg == x.Algorithm);

        return credential;
    }

    /// <summary>Gets all the signing credentials.</summary>
    /// <returns></returns>
    public async Task<IEnumerable<SigningCredentials>> GetAllSigningCredentialsAsync()
    {
        if (!_options.Enabled)
        {
            return Enumerable.Empty<SigningCredentials>();
        }

        var keyContainers = await _keyManager.GetCurrentKeysAsync();
        var credentials = keyContainers.Select(x => new SigningCredentials(x.ToSecurityKey(), x.Algorithm));

        return credentials;
    }

    /// <summary>Gets all validation keys.</summary>
    /// <returns></returns>
    public async Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
    {
        if (!_options.Enabled)
        {
            return Enumerable.Empty<SecurityKeyInfo>();
        }

        var containers = await _keyManager.GetAllKeysAsync();
        var keys = containers.Select(x => new SecurityKeyInfo
        {
            Key = x.ToSecurityKey(),
            SigningAlgorithm = x.Algorithm
        });

        return keys.ToArray();
    }
}

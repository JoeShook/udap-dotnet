using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityServer.Services.KeyManagement;

namespace Udap.Server.KeyManagement;
public class UdapKeyManager : IKeyManager
{
    /// <summary>Returns the current signing keys.</summary>
    /// <returns></returns>
    public Task<IEnumerable<KeyContainer>> GetCurrentKeysAsync()
    {
        throw new NotImplementedException();
    }

    /// <summary>Returns all the validation keys.</summary>
    /// <returns></returns>
    public Task<IEnumerable<KeyContainer>> GetAllKeysAsync()
    {
        throw new NotImplementedException();
    }
}

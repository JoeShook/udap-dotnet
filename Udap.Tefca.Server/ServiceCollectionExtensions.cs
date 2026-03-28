#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Udap.Server.Registration;
using Udap.Server.Validation;

namespace Udap.Tefca.Server;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers TEFCA community-specific validators for registration and token issuance.
    /// Call after <c>AddUdapServerConfiguration()</c> and <c>AddUdapJwtBearerClientAuthentication()</c>.
    /// </summary>
    public static IServiceCollection AddUdapTefcaValidation(this IServiceCollection services)
    {
        services.AddSingleton<ICommunityRegistrationValidator, TefcaRegistrationValidator>();
        services.AddSingleton<ICommunityTokenValidator, TefcaTokenValidator>();

        return services;
    }
}

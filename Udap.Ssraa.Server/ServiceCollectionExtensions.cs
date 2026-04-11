#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Udap.Server.Validation;
using Udap.Ssraa.Server;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class SsraaServiceCollectionExtensions
{
    /// <summary>
    /// Registers the SSRAA community token validator with default options.
    /// </summary>
    public static IServiceCollection AddUdapSsraaValidation(
        this IServiceCollection services)
    {
        return services.AddUdapSsraaValidation(_ => { });
    }

    /// <summary>
    /// Registers the SSRAA community token validator with configurable options.
    /// Use the configure action to add community names and customize required extensions.
    /// </summary>
    public static IServiceCollection AddUdapSsraaValidation(
        this IServiceCollection services,
        Action<SsraaValidationOptions> configure)
    {
        services.Configure(configure);
        services.AddSingleton<ICommunityTokenValidator, SsraaTokenValidator>();

        return services;
    }
}

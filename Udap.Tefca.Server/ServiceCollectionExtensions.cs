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
    /// Registers TEFCA community-specific validators for registration and token issuance
    /// using default options (applies to <see cref="Udap.Tefca.Model.TefcaConstants.CommunityUri"/>).
    /// Call after <c>AddUdapServerConfiguration()</c> and <c>AddUdapJwtBearerClientAuthentication()</c>.
    /// </summary>
    public static IServiceCollection AddUdapTefcaValidation(this IServiceCollection services)
    {
        return services.AddUdapTefcaValidation(_ => { });
    }

    /// <summary>
    /// Registers TEFCA community-specific validators for registration and token issuance.
    /// Use the configure action to map additional community names to the TEFCA validation pipeline.
    /// Call after <c>AddUdapServerConfiguration()</c> and <c>AddUdapJwtBearerClientAuthentication()</c>.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddUdapTefcaValidation(options =>
    /// {
    ///     options.Communities.Add("tefca://test-community");
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddUdapTefcaValidation(
        this IServiceCollection services,
        Action<TefcaValidationOptions> configure)
    {
        services.Configure(configure);
        services.AddSingleton<ICommunityRegistrationValidator, TefcaRegistrationValidator>();
        services.AddSingleton<ICommunityTokenValidator, TefcaTokenValidator>();

        return services;
    }
}

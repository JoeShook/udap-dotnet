#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common;
using Udap.Common.Certificates;
using Udap.Common.Metadata;
using Udap.Metadata.Server;
using Udap.Model;

// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddUdapMetadataServer(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return AddUdapMetadataServer<UdapMetadataOptions, UdapMetadata>(services, configuration);
    }

    public static IServiceCollection AddUdapMetadataServer<TUdapMetadataOptions, TUdapMetadata>(
        this IServiceCollection services,
        IConfiguration configuration)
    where TUdapMetadataOptions : UdapMetadataOptions
    where TUdapMetadata : UdapMetadata
    {
        services.TryAddSingleton<IPrivateCertificateStore>(sp =>
            new IssuedCertificateStore(
                sp.GetRequiredService<IOptionsMonitor<UdapFileCertStoreManifest>>(),
                sp.GetRequiredService<ILogger<IssuedCertificateStore>>()));

        services.TryAddSingleton<IUdapMetadataOptionsProvider, UdapMetadataOptionsProvider>();
        services.TryAddScoped<UdapMetaDataBuilder<TUdapMetadataOptions, TUdapMetadata>>();
        services.AddScoped<UdapMetaDataEndpoint<TUdapMetadataOptions, TUdapMetadata>>();

        return services;
    }

    /// <summary>
    /// Registers middleware that dynamically handles UDAP metadata requests at any
    /// path ending with .well-known/udap. Supports multiple base URL paths without
    /// requiring explicit route registration for each domain.
    /// </summary>
    public static IApplicationBuilder UseUdapMetadataServer(this IApplicationBuilder app)
    {
        return UseUdapMetadataServer<UdapMetadataOptions, UdapMetadata>(app);
    }

    /// <summary>
    /// Registers middleware that dynamically handles UDAP metadata requests at any
    /// path ending with .well-known/udap. Supports multiple base URL paths without
    /// requiring explicit route registration for each domain.
    /// </summary>
    public static IApplicationBuilder UseUdapMetadataServer<TUdapMetadataOptions, TUdapMetadata>(this IApplicationBuilder app)
        where TUdapMetadataOptions : UdapMetadataOptions
        where TUdapMetadata : UdapMetadata
    {
        app.UseMiddleware<UdapMetadataMiddleware<TUdapMetadataOptions, TUdapMetadata>>();

        return app;
    }
}

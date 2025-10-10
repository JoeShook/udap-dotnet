using Microsoft.EntityFrameworkCore;
using Udap.Server.Storage.DbContexts;
using Udap.Server.Storage.Options;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddUdapDbContext(
        this IServiceCollection service,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
    {
        return service.AddUdapDbContext<UdapDbContext>(storeOptionAction);
    }

    public static IServiceCollection AddUdapDbContext<TContext>(
        this IServiceCollection service,
        Action<UdapConfigurationStoreOptions>? storeOptionAction = null)
        where TContext : DbContext, IUdapDbAdminContext, IUdapDbContext
    {
        var storeOptions = new UdapConfigurationStoreOptions();
        service.AddSingleton(storeOptions);
        storeOptionAction?.Invoke(storeOptions);

        if (storeOptions.ResolveDbContextOptions != null)
        {
            if (storeOptions.EnablePooling)
            {
                if (storeOptions.PoolSize.HasValue)
                {
                    service.AddDbContextPool<TContext>(storeOptions.ResolveDbContextOptions,
                        storeOptions.PoolSize.Value);
                }
                else
                {
                    service.AddDbContextPool<TContext>(storeOptions.ResolveDbContextOptions);
                }
            }
            else
            {
                service.AddDbContext<TContext>(storeOptions.ResolveDbContextOptions);
            }
        }
        else
        {
            if (storeOptions.EnablePooling)
            {
                if (storeOptions.PoolSize.HasValue)
                {
                    service.AddDbContextPool<TContext>(
                        dbCtxBuilder => { storeOptions.UdapDbContext.Invoke(dbCtxBuilder); },
                        storeOptions.PoolSize.Value);
                }
                else
                {
                    service.AddDbContextPool<TContext>(
                        dbCtxBuilder => { storeOptions.UdapDbContext.Invoke(dbCtxBuilder); });
                }
            }
            else
            {
                service.AddDbContext<TContext>(dbCtxBuilder =>
                {
                    storeOptions.UdapDbContext.Invoke(dbCtxBuilder);
                });
            }
        }

        service.AddScoped<IUdapDbAdminContext>(sp => sp.GetRequiredService<TContext>());
        service.AddScoped<IUdapDbContext>(sp => sp.GetRequiredService<TContext>());

        return service;
    }
}

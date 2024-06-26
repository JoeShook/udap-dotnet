﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.EntityFramework.Storage;
using Duende.IdentityServer.Models;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Models;
using Udap.Server.Storage.Stores;
using Udap.Server.Stores;
using Udap.Util.Extensions;
using ILogger = Serilog.ILogger;

namespace UdapDb;

public static class Seed_GCP_Auth_Server
{
    private static Anchor anchor;

    /// <summary>
    /// Load some test dat
    /// </summary>
    /// <param name="connectionString"></param>
    /// <param name="certStoreBasePath">Test certs base path</param>
    /// <param name="logger"></param>
    public static async Task<int> EnsureSeedData(string connectionString, string certStoreBasePath, ILogger logger)
    {
        var services = new ServiceCollection();

        services.AddLogging(c => c.AddSerilog());

        services.AddOperationalDbContext<NpgsqlPersistedGrantDbContext>(options =>
        {
            options.ConfigureDbContext = db => db.UseNpgsql(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName)
                    .MigrationsHistoryTable("__migrations_history", "udap"));
        });
        services.AddConfigurationDbContext<NpgsqlConfigurationDbContext>(options =>
        {
            options.ConfigureDbContext = db => db.UseNpgsql(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName)
                    .MigrationsHistoryTable("__migrations_history", "udap"));
        });

        services.AddScoped<IUdapClientRegistrationStore, UdapClientRegistrationStore>();
        services.AddUdapDbContext(options =>
        {
            options.UdapDbContext = db => db.UseNpgsql(connectionString,
                sql => sql.MigrationsAssembly(typeof(Program).Assembly.FullName)
                    .MigrationsHistoryTable("__migrations_history", "udap"));
        });

        await using var serviceProvider = services.BuildServiceProvider();
        using var serviceScope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();

        await serviceScope.ServiceProvider.GetRequiredService<NpgsqlPersistedGrantDbContext>().Database.MigrateAsync();
        var configDbContext = serviceScope.ServiceProvider.GetRequiredService<NpgsqlConfigurationDbContext>();
        await configDbContext.Database.MigrateAsync();

        var udapContext = serviceScope.ServiceProvider.GetRequiredService<UdapDbContext>();
        await udapContext.Database.MigrateAsync();


        var clientRegistrationStore = serviceScope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();

        if (!udapContext.Communities.Any(c => c.Name == "udap://stage.healthtogo.me/"))
        {
            var community = new Community { Name = "udap://stage.healthtogo.me/" };
            community.Enabled = true;
            community.Default = true;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        if (!udapContext.Communities.Any(c => c.Name == "udap://fhirlabs.net/"))
        {
            var community = new Community { Name = "udap://fhirlabs.net/" };
            community.Enabled = true;
            community.Default = false;
            udapContext.Communities.Add(community);
            await udapContext.SaveChangesAsync();
        }

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        //
        // Anchor surefhirlabs_community
        //
        var sureFhirLabsAnchor = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "surefhirlabs_community/SureFhirLabs_CA.cer"));

        if ((await clientRegistrationStore.GetAnchors("udap://fhirlabs.net/"))
            .All(a => a.Thumbprint != sureFhirLabsAnchor.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://fhirlabs.net/");

            anchor = new Anchor
            {
                BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                Name = sureFhirLabsAnchor.Subject,
                Community = community,
                X509Certificate = sureFhirLabsAnchor.ToPemFormat(),
                Thumbprint = sureFhirLabsAnchor.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
        }

        var intermediateCert = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath,
                "surefhirlabs_community/intermediates/SureFhirLabs_Intermediate.cer"));

        if ((await clientRegistrationStore.GetIntermediateCertificates())
            .All(a => a.Thumbprint != intermediateCert.Thumbprint))
        {
            var anchor = udapContext.Anchors.Single(a => a.Thumbprint == sureFhirLabsAnchor.Thumbprint);

            //
            // Intermediate surefhirlabs_community
            //
            var x509Certificate2Collection = await clientRegistrationStore.GetIntermediateCertificates();
            
            if (x509Certificate2Collection != null && x509Certificate2Collection.ToList()
                    .All(r => r.Thumbprint != intermediateCert.Thumbprint))
            {

                udapContext.IntermediateCertificates.Add(new Intermediate
                {
                    BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                    EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                    Name = intermediateCert.Subject,
                    X509Certificate = intermediateCert.ToPemFormat(),
                    Thumbprint = intermediateCert.Thumbprint,
                    Enabled = true,
                    Anchor = anchor
                });

                await udapContext.SaveChangesAsync();
            }
        }


        //
        // Anchor for Community udap://stage.healthtogo.me/
        //
        var emrDirectTestCA = new X509Certificate2(
            Path.Combine(assemblyPath!, certStoreBasePath, "EmrDirect/EMRDirectTestCA.crt"));

        if ((await clientRegistrationStore.GetAnchors("udap://stage.healthtogo.me/"))
            .All(a => a.Thumbprint != emrDirectTestCA.Thumbprint))
        {
            var community = udapContext.Communities.Single(c => c.Name == "udap://stage.healthtogo.me/");

            anchor = new Anchor
            {
                BeginDate = emrDirectTestCA.NotBefore.ToUniversalTime(),
                EndDate = emrDirectTestCA.NotAfter.ToUniversalTime(),
                Name = emrDirectTestCA.Subject,
                Community = community,
                X509Certificate = emrDirectTestCA.ToPemFormat(),
                Thumbprint = emrDirectTestCA.Thumbprint,
                Enabled = true
            };

            udapContext.Anchors.Add(anchor);
            await udapContext.SaveChangesAsync();
        }


        Func<string, bool> treatmentSpecification = r => r is "Patient" or "AllergyIntolerance" or "Condition" or "Encounter";

        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("patient", treatmentSpecification), 1);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("user", treatmentSpecification), 1);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes("system", treatmentSpecification), 1);

        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("patient", treatmentSpecification), 2);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("user", treatmentSpecification), 2);
        await SeedFhirScopes(configDbContext, Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes("system", treatmentSpecification), 2);


        //
        // openid
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.OpenId))
        {
            var identityResource = new IdentityResources.OpenId();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // fhirUser
        //
        if (configDbContext.IdentityResources.All(i => i.Name != UdapConstants.StandardScopes.FhirUser))
        {
            var fhirUserIdentity = new UdapIdentityResources.FhirUser();
            configDbContext.IdentityResources.Add(fhirUserIdentity.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // udap
        //
        if (configDbContext.ApiScopes.All(i => i.Name != UdapConstants.StandardScopes.Udap))
        {
            var udapIdentity = new UdapApiScopes.Udap();
            configDbContext.ApiScopes.Add(udapIdentity.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // profile
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.Profile))
        {
            var identityResource = new UdapIdentityResources.Profile();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        //
        // email
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.Email))
        {
            var identityResource = new IdentityResources.Email();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

        return 0;
    }


    private static async Task SeedFhirScopes(NpgsqlConfigurationDbContext configDbContext, HashSet<string>? seedScopes, int version)
    {
        var apiScopes = configDbContext.ApiScopes
            .Include(s => s.Properties)
            .Select(s => s)
            .ToList();

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("system")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "system")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                if (apiScope.Name.StartsWith("system/*."))
                {
                    apiScope.ShowInDiscoveryDocument = true;
                    apiScope.Enabled = false;
                }
                apiScope.Properties.Add("udap_prefix", "system");
                apiScope.Properties.Add("smart_version", version.ToString());
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("user")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "user")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                if (apiScope.Name.StartsWith("user/*."))
                {
                    apiScope.ShowInDiscoveryDocument = true;
                    apiScope.Enabled = false;
                }
                apiScope.Properties.Add("udap_prefix", "user");
                apiScope.Properties.Add("smart_version", version.ToString());
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("patient")))
        {
            if (!apiScopes.Any(s => s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "patient")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                if (apiScope.Name.StartsWith("patient/*."))
                {
                    apiScope.ShowInDiscoveryDocument = true;
                    apiScope.Enabled = false;
                }
                apiScope.Properties.Add("udap_prefix", "patient");
                apiScope.Properties.Add("smart_version", version.ToString());
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        await configDbContext.SaveChangesAsync();
        
    }
}

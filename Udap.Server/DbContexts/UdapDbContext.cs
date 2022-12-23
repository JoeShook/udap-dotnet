﻿#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System.Net.Sockets;
using Duende.IdentityServer.EntityFramework.Entities;
using Udap.Server.Entities;
using Udap.Server.Extensions;
using Udap.Server.Options;

namespace Udap.Server.DbContexts;

public interface IUdapDbAdminContext : IDisposable
{
    DbSet<UdapClient> Clients { get; set; }
    DbSet<Anchor> Anchors { get; set; }
    DbSet<RootCertificate> RootCertificates { get; set; }
    DbSet<Community> Communities { get; set; }
    DbSet<Certification> Certifications { get; set; }
    DbSet<UdapClientSecrets> UdapClientSecrets { get; set; }
    /// <summary>
    /// Saves the changes.
    /// </summary>
    /// <returns></returns>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public interface IUdapDbContext : IDisposable
{
    DbSet<UdapClient> Clients { get; set; }
    DbSet<Anchor> Anchors { get; set; }
    DbSet<RootCertificate> RootCertificates { get; set; }
    DbSet<Community> Communities { get; set; }
    DbSet<Certification> Certifications { get; set; }
    DbSet<UdapClientSecrets> UdapClientSecrets { get; set; }
}

public class UdapDbContext : UdapDbContext<UdapDbContext>
{
    public UdapDbContext(DbContextOptions<UdapDbContext> options) : base(options)
    {

    }
}

public class UdapDbContext<TContext> : DbContext, IUdapDbAdminContext, IUdapDbContext
    where TContext : DbContext, IUdapDbAdminContext, IUdapDbContext
{
    /// <summary>
    /// The udap store options.
    /// Overrides ConfigurationStoreOptions.
    /// </summary>
    public UdapConfigurationStoreOptions UdapStoreOptions { get; set; }
    

    public DbSet<Anchor> Anchors { get; set; }
    public DbSet<RootCertificate> RootCertificates { get; set; }

    public DbSet<UdapClient> Clients { get; set; }
    public DbSet<Community> Communities { get; set; }
    public DbSet<Certification> Certifications { get; set; }
    public DbSet<UdapClientSecrets> UdapClientSecrets { get; set; }

    public UdapDbContext(DbContextOptions<TContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        if (UdapStoreOptions is null)
        {
            UdapStoreOptions = this.GetService<UdapConfigurationStoreOptions>();

            if (UdapStoreOptions is null)
            {
                throw new ArgumentNullException(nameof(UdapStoreOptions), "UdapConfigurationStoreOptions must be configured in the DI system.");
            }
        }
        
        modelBuilder.ConfigureUdapContext(UdapStoreOptions);

        //
        // Need these mappings to correct things like the table names
        //
        // modelBuilder.ConfigureClientContext(UdapStoreOptions);
        // modelBuilder.ConfigureResourcesContext(UdapStoreOptions);
        // modelBuilder.ConfigureIdentityProviderContext(UdapStoreOptions);

        //
        // Reference to DbSet<Client> builds the schema of all Clients table related entities.  
        // Do not want to own the ConfigurationDbContext from Identity Server, so exclude them
        // from EF migration.
        //
        // modelBuilder.Entity<Duende.IdentityServer.EntityFramework.Entities.Client>().ToTable("Clients", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientClaim>().ToTable("ClientClaims", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientCorsOrigin>().ToTable("ClientCorsOrigins", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientGrantType>().ToTable("ClientGrantTypes", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientIdPRestriction>().ToTable("ClientIdPRestrictions", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientPostLogoutRedirectUri>().ToTable("ClientPostLogoutRedirectUris", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientProperty>().ToTable("ClientProperties", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientRedirectUri>().ToTable("ClientRedirectUris", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientSecret>().ToTable("ClientSecrets", t => t.ExcludeFromMigrations());
        modelBuilder.Entity<ClientScope>().ToTable("ClientScopes", t => t.ExcludeFromMigrations());
        
        base.OnModelCreating(modelBuilder);
    }
}


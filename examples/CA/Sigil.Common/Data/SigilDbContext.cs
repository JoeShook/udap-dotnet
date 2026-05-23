#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Sigil.Common.Data.Entities;

namespace Sigil.Common.Data;

public class SigilDbContext : DbContext
{
    public SigilDbContext(DbContextOptions<SigilDbContext> options) : base(options)
    {
    }

    public DbSet<TrustDomain> TrustDomains => Set<TrustDomain>();
    public DbSet<TrustDomainBaseUrl> TrustDomainBaseUrls => Set<TrustDomainBaseUrl>();
    public DbSet<CaCertificate> CaCertificates => Set<CaCertificate>();
    public DbSet<IssuedCertificate> IssuedCertificates => Set<IssuedCertificate>();
    public DbSet<Crl> Crls => Set<Crl>();
    public DbSet<CertificateRevocation> CertificateRevocations => Set<CertificateRevocation>();
    public DbSet<CertificateTemplate> CertificateTemplates => Set<CertificateTemplate>();
    public DbSet<SanList> SanLists => Set<SanList>();
    public DbSet<DidTemplate> DidTemplates => Set<DidTemplate>();
    public DbSet<DidDocument> DidDocuments => Set<DidDocument>();
    public DbSet<VerificationMethod> VerificationMethods => Set<VerificationMethod>();
    public DbSet<CredentialSchema> CredentialSchemas => Set<CredentialSchema>();
    public DbSet<IssuedCredential> IssuedCredentials => Set<IssuedCredential>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema("sigil");

        // TrustDomain
        modelBuilder.Entity<TrustDomain>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.Name).IsUnique();
        });

        // TrustDomainBaseUrl
        modelBuilder.Entity<TrustDomainBaseUrl>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Url).HasMaxLength(500).IsRequired();
            entity.Property(e => e.PublishingBasePath).HasMaxLength(500);
            entity.HasIndex(e => new { e.TrustDomainId, e.SortOrder });

            entity.HasOne(e => e.TrustDomain)
                .WithMany(c => c.BaseUrls)
                .HasForeignKey(e => e.TrustDomainId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // CaCertificate (self-referential for root + intermediate hierarchy)
        modelBuilder.Entity<CaCertificate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Thumbprint).IsUnique();
            entity.HasIndex(e => e.TrustDomainId);
            entity.Property(e => e.Subject).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Thumbprint).HasMaxLength(64).IsRequired();
            entity.Property(e => e.SerialNumber).HasMaxLength(100).IsRequired();
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(20);
            entity.Property(e => e.StoreProviderHint).HasMaxLength(200);
            entity.Ignore(e => e.IsRootCa);

            entity.HasOne(e => e.TrustDomain)
                .WithMany(c => c.CaCertificates)
                .HasForeignKey(e => e.TrustDomainId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Parent)
                .WithMany(e => e.Children)
                .HasForeignKey(e => e.ParentId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        // IssuedCertificate
        modelBuilder.Entity<IssuedCertificate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Thumbprint).IsUnique();
            entity.HasIndex(e => e.IssuingCaCertificateId);
            entity.Property(e => e.Subject).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Thumbprint).HasMaxLength(64).IsRequired();
            entity.Property(e => e.SerialNumber).HasMaxLength(100).IsRequired();
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(20);
            entity.Property(e => e.StoreProviderHint).HasMaxLength(200);

            entity.HasOne(e => e.IssuingCaCertificate)
                .WithMany(ca => ca.IssuedCertificates)
                .HasForeignKey(e => e.IssuingCaCertificateId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Template)
                .WithMany(t => t.IssuedCertificates)
                .HasForeignKey(e => e.TemplateId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // Crl
        modelBuilder.Entity<Crl>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.CaCertificateId);
            entity.Property(e => e.SignatureAlgorithm).HasMaxLength(50);
            entity.Property(e => e.FileName).HasMaxLength(200);

            entity.HasOne(e => e.CaCertificate)
                .WithMany(ca => ca.Crls)
                .HasForeignKey(e => e.CaCertificateId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // CertificateRevocation
        modelBuilder.Entity<CertificateRevocation>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.CrlId);
            entity.Property(e => e.RevokedCertSerialNumber).HasMaxLength(100).IsRequired();
            entity.Property(e => e.RevokedCertThumbprint).HasMaxLength(64);

            entity.HasOne(e => e.Crl)
                .WithMany(crl => crl.Revocations)
                .HasForeignKey(e => e.CrlId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // CertificateTemplate
        modelBuilder.Entity<CertificateTemplate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.Name).IsUnique();
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(20);
            entity.Property(e => e.SubjectTemplate).HasMaxLength(500);
            entity.Property(e => e.EcdsaCurve).HasMaxLength(20);
            entity.Property(e => e.HashAlgorithm).HasMaxLength(10);
            entity.Property(e => e.CdpUrlTemplate).HasMaxLength(500);
            entity.Property(e => e.AiaUrlTemplate).HasMaxLength(500);
            entity.Property(e => e.SubjectAltNameTypes).HasMaxLength(100);

            entity.HasMany(e => e.SanLists)
                .WithMany(s => s.Templates)
                .UsingEntity("CertificateTemplateSanList");
        });

        // SanList
        modelBuilder.Entity<SanList>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.Name).IsUnique();
        });

        // DidTemplate
        modelBuilder.Entity<DidTemplate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.Name).IsUnique();
            entity.Property(e => e.Method).HasMaxLength(50).IsRequired();
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(20).IsRequired();
            entity.Property(e => e.EcdsaCurve).HasMaxLength(20);
            entity.Property(e => e.DefaultPurposes).HasMaxLength(200).IsRequired();
        });

        // DidDocument
        modelBuilder.Entity<DidDocument>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Did).HasMaxLength(500).IsRequired();
            entity.HasIndex(e => e.Did).IsUnique();
            entity.Property(e => e.Method).HasMaxLength(50).IsRequired();
            entity.HasIndex(e => e.TrustDomainId);

            entity.HasOne(e => e.TrustDomain)
                .WithMany(td => td.DidDocuments)
                .HasForeignKey(e => e.TrustDomainId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Template)
                .WithMany(t => t.DidDocuments)
                .HasForeignKey(e => e.DidTemplateId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // VerificationMethod
        modelBuilder.Entity<VerificationMethod>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.MethodId).HasMaxLength(500).IsRequired();
            entity.HasIndex(e => e.MethodId);
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(20).IsRequired();
            entity.Property(e => e.Provider).HasMaxLength(50).IsRequired();
            entity.Property(e => e.KeyIdentifier).HasMaxLength(200).IsRequired();
            entity.Property(e => e.PublicKeyMultibase).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Purposes).HasMaxLength(200).IsRequired();

            entity.HasOne(e => e.DidDocument)
                .WithMany(d => d.VerificationMethods)
                .HasForeignKey(e => e.DidDocumentId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // CredentialSchema
        modelBuilder.Entity<CredentialSchema>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.Name).IsUnique();
            entity.Property(e => e.TypeUri).HasMaxLength(500);
            entity.Property(e => e.Format).HasMaxLength(50).IsRequired();
            entity.Property(e => e.ClaimsSchemaJson).IsRequired();
        });

        // IssuedCredential
        modelBuilder.Entity<IssuedCredential>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.CredentialId).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.CredentialId).IsUnique();
            entity.Property(e => e.SubjectDid).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Format).HasMaxLength(50).IsRequired();
            entity.Property(e => e.SignedCredential).IsRequired();
            entity.Property(e => e.ClaimsJson).IsRequired();
            entity.HasIndex(e => e.IssuerDidDocumentId);

            entity.HasOne(e => e.TrustDomain)
                .WithMany(td => td.IssuedCredentials)
                .HasForeignKey(e => e.TrustDomainId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Schema)
                .WithMany(s => s.IssuedCredentials)
                .HasForeignKey(e => e.CredentialSchemaId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(e => e.IssuerDid)
                .WithMany(d => d.IssuedCredentials)
                .HasForeignKey(e => e.IssuerDidDocumentId)
                .OnDelete(DeleteBehavior.Restrict);
        });
    }
}

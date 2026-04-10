using Microsoft.EntityFrameworkCore;
using Sigil.Common.Data.Entities;

namespace Sigil.Common.Data;

public class SigilDbContext : DbContext
{
    public SigilDbContext(DbContextOptions<SigilDbContext> options) : base(options)
    {
    }

    public DbSet<Community> Communities => Set<Community>();
    public DbSet<CaCertificate> CaCertificates => Set<CaCertificate>();
    public DbSet<IssuedCertificate> IssuedCertificates => Set<IssuedCertificate>();
    public DbSet<Crl> Crls => Set<Crl>();
    public DbSet<CertificateRevocation> CertificateRevocations => Set<CertificateRevocation>();
    public DbSet<CertificateTemplate> CertificateTemplates => Set<CertificateTemplate>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<JobExecution> JobExecutions => Set<JobExecution>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema("sigil");

        // Community
        modelBuilder.Entity<Community>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.HasIndex(e => e.Name).IsUnique();
        });

        // CaCertificate (self-referential for root + intermediate hierarchy)
        modelBuilder.Entity<CaCertificate>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Thumbprint).IsUnique();
            entity.HasIndex(e => e.CommunityId);
            entity.Property(e => e.Subject).HasMaxLength(500).IsRequired();
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Thumbprint).HasMaxLength(64).IsRequired();
            entity.Property(e => e.SerialNumber).HasMaxLength(100).IsRequired();
            entity.Property(e => e.KeyAlgorithm).HasMaxLength(20);
            entity.Property(e => e.StoreProviderHint).HasMaxLength(50);
            entity.Ignore(e => e.IsRootCa);

            entity.HasOne(e => e.Community)
                .WithMany(c => c.CaCertificates)
                .HasForeignKey(e => e.CommunityId)
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
        });

        // Job
        modelBuilder.Entity<Job>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.CronExpression).HasMaxLength(100);
            entity.Property(e => e.TargetEntityType).HasMaxLength(50);
            entity.HasIndex(e => e.NextRunAt);
        });

        // JobExecution
        modelBuilder.Entity<JobExecution>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.JobId);

            entity.HasOne(e => e.Job)
                .WithMany(j => j.Executions)
                .HasForeignKey(e => e.JobId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}

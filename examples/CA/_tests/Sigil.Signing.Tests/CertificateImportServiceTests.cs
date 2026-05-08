#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;

namespace Sigil.Signing.Tests;

public class CertificateImportServiceTests
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory = new TestDbContextFactory();

    private CertificateImportService CreateService() =>
        new(_dbFactory, NullLogger<CertificateImportService>.Instance);

    [Fact]
    public async Task ImportParsed_RootCa_CreatesEntity()
    {
        var communityId = await SeedCommunityAsync();
        var parsed = CreateParsedRootCa();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(parsed, communityId);

        result.Success.Should().BeTrue();
        result.AlreadyExists.Should().BeFalse();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FirstOrDefaultAsync(c => c.CommunityId == communityId);
        ca.Should().NotBeNull();
        ca!.Subject.Should().Contain("Root");
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_EndEntity_WithCa_CreatesIssuedCert()
    {
        var (communityId, caId) = await SeedCommunityWithCaAsync();
        var parsed = CreateParsedEndEntity();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(
            parsed, communityId, issuingCaId: caId);

        result.Success.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var issued = await db.IssuedCertificates.FirstOrDefaultAsync();
        issued.Should().NotBeNull();
        issued!.IssuingCaCertificateId.Should().Be(caId);
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_EndEntity_NoCaMatch_ReturnsNeedsCaSelection()
    {
        var communityId = await SeedCommunityAsync();
        var parsed = CreateParsedEndEntity();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(parsed, communityId);

        result.NeedsCaSelection.Should().BeTrue();
        result.Success.Should().BeFalse();
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_DuplicateThumbprint_ReturnsMerged()
    {
        var communityId = await SeedCommunityAsync();
        var service = CreateService();

        var parsed1 = CreateParsedRootCa();
        var result1 = await service.ImportParsedCertificateAsync(parsed1, communityId);
        result1.Success.Should().BeTrue();

        // Import the same cert again — should merge, not duplicate
        var parsed2 = CreateParsedRootCaFrom(parsed1.Certificate);
        var result2 = await service.ImportParsedCertificateAsync(parsed2, communityId);

        result2.Success.Should().BeTrue();
        result2.AlreadyExists.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var count = await db.CaCertificates.CountAsync(c => c.CommunityId == communityId);
        count.Should().Be(1);

        parsed1.Certificate.Dispose();
        parsed2.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_DuplicateWithPfx_MergesPfxBytes()
    {
        var communityId = await SeedCommunityAsync();
        var service = CreateService();

        var parsed1 = CreateParsedRootCa(hasPrivateKey: false);
        await service.ImportParsedCertificateAsync(parsed1, communityId);

        // Import same cert again but with PFX bytes this time
        var pfxBytes = parsed1.Certificate.Export(X509ContentType.Pkcs12, "pass");
        var parsed2 = CreateParsedRootCaFrom(parsed1.Certificate, hasPrivateKey: true);
        var result = await service.ImportParsedCertificateAsync(
            parsed2, communityId, password: "pass", rawFileOverride: pfxBytes);

        result.Success.Should().BeTrue();
        result.AlreadyExists.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FirstAsync(c => c.Thumbprint == parsed1.Certificate.Thumbprint);
        ca.EncryptedPfxBytes.Should().NotBeNull();
        ca.PfxPassword.Should().Be("pass");

        parsed1.Certificate.Dispose();
        parsed2.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_CustomName_UsesProvidedName()
    {
        var communityId = await SeedCommunityAsync();
        var parsed = CreateParsedRootCa();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(
            parsed, communityId, name: "My Custom CA");

        result.ImportedName.Should().Be("My Custom CA");
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_IntermediateCa_WithExplicitParent_SetsParentId()
    {
        var (communityId, caId) = await SeedCommunityWithCaAsync();
        var parsed = CreateParsedIntermediateCa();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(
            parsed, communityId, issuingCaId: caId);

        result.Success.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var intermediate = await db.CaCertificates
            .FirstOrDefaultAsync(c => c.Thumbprint == parsed.Certificate.Thumbprint);
        intermediate.Should().NotBeNull();
        intermediate!.ParentId.Should().Be(caId);
        parsed.Certificate.Dispose();
    }

    #region Helpers

    private async Task<int> SeedCommunityAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var community = new Community { Name = "Import Test", Enabled = true };
        db.Communities.Add(community);
        await db.SaveChangesAsync();
        return community.Id;
    }

    private async Task<(int CommunityId, int CaId)> SeedCommunityWithCaAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var community = new Community { Name = "Import Test", Enabled = true };
        db.Communities.Add(community);
        await db.SaveChangesAsync();

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Seed CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var ca = new CaCertificate
        {
            CommunityId = community.Id,
            Name = "Seed-CA",
            Subject = "CN=Seed CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        return (community.Id, ca.Id);
    }

    private static ParsedCertificate CreateParsedRootCa(bool hasPrivateKey = true)
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Root CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = hasPrivateKey ? cert.Export(X509ContentType.Pkcs12, "test") : cert.RawData,
            FileName = "test-root.pfx",
            DetectedRole = DetectedCertRole.RootCa,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = hasPrivateKey
        };
    }

    private static ParsedCertificate CreateParsedIntermediateCa()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Intermediate CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = cert.Export(X509ContentType.Pkcs12, "test"),
            FileName = "test-intermediate.pfx",
            DetectedRole = DetectedCertRole.IntermediateCa,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = true
        };
    }

    private static ParsedCertificate CreateParsedEndEntity()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test End Entity", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = cert.Export(X509ContentType.Pkcs12, "test"),
            FileName = "test-client.pfx",
            DetectedRole = DetectedCertRole.EndEntity,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = true
        };
    }

    private static ParsedCertificate CreateParsedRootCaFrom(
        X509Certificate2 existingCert, bool hasPrivateKey = false)
    {
        var cert = new X509Certificate2(existingCert.RawData);

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = cert.RawData,
            FileName = "dup.pfx",
            DetectedRole = DetectedCertRole.RootCa,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = hasPrivateKey
        };
    }

    #endregion
}

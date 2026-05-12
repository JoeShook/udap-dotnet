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
using NSubstitute;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;
using Sigil.Common.Services.Jobs;
using Sigil.Common.Services.Signing;
using Sigil.Common.ViewModels;

namespace Sigil.Signing.Tests;

public class CertificateManagementServiceTests
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory = new TestDbContextFactory();
    private readonly ChainValidationService _chainValidator;
    private readonly CrlGenerationService _crlGenService;

    public CertificateManagementServiceTests()
    {
        var httpFactory = Substitute.For<IHttpClientFactory>();
        httpFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient());

        _chainValidator = new ChainValidationService(
            _dbFactory,
            httpFactory,
            NullLogger<ChainValidationService>.Instance);

        _crlGenService = new CrlGenerationService(
            _dbFactory,
            NullLogger<CrlGenerationService>.Instance,
            new LocalSigningProvider());
    }

    private CertificateManagementService CreateService() =>
        new(_dbFactory, NullLogger<CertificateManagementService>.Instance,
            _chainValidator, _crlGenService);

    [Fact]
    public async Task RenameAsync_CaCertificate_UpdatesName()
    {
        var caId = await SeedCaCertificateAsync("Original Name");
        var service = CreateService();

        var result = await service.RenameAsync(caId, "CaCertificate", "New Name");

        result.Success.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FindAsync(caId);
        ca!.Name.Should().Be("New Name");
    }

    [Fact]
    public async Task RenameAsync_IssuedCertificate_UpdatesName()
    {
        var (_, issuedId) = await SeedCaAndIssuedAsync();
        var service = CreateService();

        var result = await service.RenameAsync(issuedId, "IssuedCertificate", "Renamed Cert");

        result.Success.Should().BeTrue();
    }

    [Fact]
    public async Task RenameAsync_EmptyName_ReturnsFail()
    {
        var caId = await SeedCaCertificateAsync("Some CA");
        var service = CreateService();

        var result = await service.RenameAsync(caId, "CaCertificate", "  ");

        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task RenameAsync_NonexistentId_ReturnsFail()
    {
        var service = CreateService();

        var result = await service.RenameAsync(99999, "CaCertificate", "Name");

        result.Success.Should().BeFalse();
        result.Error.Should().Contain("not found");
    }

    [Fact]
    public async Task SetAutoRenewAsync_TogglesFlag()
    {
        var caId = await SeedCaCertificateAsync("Auto CA");
        var service = CreateService();

        await service.SetAutoRenewAsync(caId, "CaCertificate", false);

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FindAsync(caId);
        ca!.AutoRenew.Should().BeFalse();
    }

    [Fact]
    public async Task ArchiveAsync_CaCertificate_SetsFlags()
    {
        var caId = await SeedCaCertificateAsync("Archive Me");
        var service = CreateService();

        var result = await service.ArchiveAsync(caId, "CaCertificate");

        result.Success.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FindAsync(caId);
        ca!.IsArchived.Should().BeTrue();
        ca.ArchivedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task ArchiveAsync_NonexistentId_ReturnsFail()
    {
        var service = CreateService();

        var result = await service.ArchiveAsync(99999, "CaCertificate");

        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteAsync_CaWithChildren_Blocked()
    {
        var (caId, _) = await SeedCaAndIssuedAsync();
        var service = CreateService();

        var result = await service.DeleteAsync(caId, "CaCertificate");

        result.Success.Should().BeFalse();
        result.Error.Should().Contain("issued cert");
    }

    [Fact]
    public async Task DeleteAsync_CaWithoutChildren_Succeeds()
    {
        var caId = await SeedCaCertificateAsync("Lone CA");
        var service = CreateService();

        var result = await service.DeleteAsync(caId, "CaCertificate");

        result.Success.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FindAsync(caId);
        ca.Should().BeNull();
    }

    [Fact]
    public async Task DeleteAsync_IssuedCertificate_Succeeds()
    {
        var (_, issuedId) = await SeedCaAndIssuedAsync();
        var service = CreateService();

        var result = await service.DeleteAsync(issuedId, "IssuedCertificate");

        result.Success.Should().BeTrue();
    }

    [Fact]
    public async Task MoveAsync_CaCertificate_ChangesCommunity()
    {
        var caId = await SeedCaCertificateAsync("Mobile CA");
        int targetCommunityId;

        await using (var db = _dbFactory.CreateDbContext())
        {
            var target = new Community { Name = "Target", Enabled = true };
            db.Communities.Add(target);
            await db.SaveChangesAsync();
            targetCommunityId = target.Id;
        }

        var service = CreateService();

        var result = await service.MoveAsync(caId, "CaCertificate", targetCommunityId);

        result.Success.Should().BeTrue();

        await using var db2 = _dbFactory.CreateDbContext();
        var ca = await db2.CaCertificates.FindAsync(caId);
        ca!.CommunityId.Should().Be(targetCommunityId);
        ca.ParentId.Should().BeNull();
    }

    [Fact]
    public async Task RevokeAsync_CaCertificate_SetsRevokedFlags()
    {
        var caId = await SeedCaCertificateAsync("Revoke Me");
        var service = CreateService();

        var result = await service.RevokeAsync(caId, "CaCertificate", 1);

        result.Success.Should().BeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FindAsync(caId);
        ca!.IsRevoked.Should().BeTrue();
        ca.RevokedAt.Should().NotBeNull();
        ca.RevocationReason.Should().Be(1);
    }

    [Fact]
    public async Task GetNodeDetailsAsync_CaCertificate_ReturnsDetails()
    {
        var caId = await SeedCaCertificateAsync("Detail CA", hasPrivateKey: true);
        var service = CreateService();

        var details = await service.GetNodeDetailsAsync(caId, "CaCertificate");

        details.Pem.Should().NotBeNullOrEmpty();
        details.HasPrivateKey.Should().BeTrue();
        details.AutoRenew.Should().BeTrue();
    }

    [Fact]
    public async Task GetCommunityTreeAsync_BuildsTree()
    {
        var (caId, _) = await SeedCaAndIssuedAsync();
        var service = CreateService();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FindAsync(caId);

        var treeData = await service.GetCommunityTreeAsync(ca!.CommunityId);

        treeData.CommunityName.Should().Be("Test Community");
        treeData.TreeNodes.Should().ContainSingle();
        treeData.TreeNodes[0].EntityType.Should().Be("CaCertificate");
        treeData.TreeNodes[0].Children.Should().ContainSingle(c => c.EntityType == "IssuedCertificate");
    }

    [Fact]
    public void DeriveStatus_Expired_ReturnsExpired()
    {
        var status = CertificateManagementService.DeriveStatus(
            "AABB", DateTime.UtcNow.AddDays(-1), false, new());

        status.Should().Be(CertificateStatus.Expired);
    }

    [Fact]
    public void DeriveStatus_Revoked_ReturnsRevoked()
    {
        var status = CertificateManagementService.DeriveStatus(
            "AABB", DateTime.UtcNow.AddYears(1), true, new());

        status.Should().Be(CertificateStatus.Revoked);
    }

    [Fact]
    public void DeriveStatus_ExpiringSoon_ReturnsExpiring()
    {
        var status = CertificateManagementService.DeriveStatus(
            "AABB", DateTime.UtcNow.AddDays(15), false, new());

        status.Should().Be(CertificateStatus.Expiring);
    }

    [Fact]
    public void DeriveStatus_Valid_ReturnsValid()
    {
        var status = CertificateManagementService.DeriveStatus(
            "AABB", DateTime.UtcNow.AddYears(1), false, new());

        status.Should().Be(CertificateStatus.Valid);
    }

    #region Helpers

    private async Task<int> SeedCaCertificateAsync(string name, bool hasPrivateKey = false)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();

        var community = await db.Communities.FirstOrDefaultAsync();
        if (community == null)
        {
            community = new Community { Name = "Test Community", Enabled = true };
            db.Communities.Add(community);
            await db.SaveChangesAsync();
        }

        var ca = new CaCertificate
        {
            CommunityId = community.Id,
            Name = name,
            Subject = $"CN={name}",
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = hasPrivateKey ? cert.Export(X509ContentType.Pkcs12, "test") : null,
            PfxPassword = hasPrivateKey ? "test" : null,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter
        };

        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();
        return ca.Id;
    }

    private async Task<(int CaId, int IssuedId)> SeedCaAndIssuedAsync()
    {
        using var rsa = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        using var issuedRsa = RSA.Create(2048);
        var issuedReq = new CertificateRequest("CN=Issued Cert", issuedRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var issuedCert = issuedReq.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();

        var community = new Community { Name = "Test Community", Enabled = true };
        db.Communities.Add(community);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            CommunityId = community.Id,
            Name = "Test CA",
            Subject = "CN=Test CA",
            X509CertificatePem = caCert.ExportCertificatePem(),
            Thumbprint = caCert.Thumbprint,
            SerialNumber = caCert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = ca.Id,
            Name = "Issued Cert",
            Subject = "CN=Issued Cert",
            X509CertificatePem = issuedCert.ExportCertificatePem(),
            Thumbprint = issuedCert.Thumbprint,
            SerialNumber = issuedCert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = issuedCert.NotBefore,
            NotAfter = issuedCert.NotAfter
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();

        return (ca.Id, issued.Id);
    }

    #endregion
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;

namespace Sigil.Signing.Tests;

public class TemplateServiceTests
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory = new TestDbContextFactory();

    private TemplateService CreateService() =>
        new(_dbFactory, NullLogger<TemplateService>.Instance);

    [Fact]
    public async Task GetAll_EmptyDb_ReturnsEmpty()
    {
        var service = CreateService();

        var result = await service.GetAllAsync();

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task SaveAsync_NewTemplate_CreatesAndReturnsWithId()
    {
        var service = CreateService();
        var template = new CertificateTemplate
        {
            Name = "Test Template",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365
        };

        var saved = await service.SaveAsync(template);

        saved.Id.Should().BeGreaterThan(0);
        saved.Name.Should().Be("Test Template");
    }

    [Fact]
    public async Task SaveAsync_ExistingTemplate_Updates()
    {
        var service = CreateService();
        var template = new CertificateTemplate
        {
            Name = "Original",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365
        };
        var saved = await service.SaveAsync(template);

        var updated = new CertificateTemplate
        {
            Id = saved.Id,
            Name = "Updated",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 4096,
            ValidityDays = 730
        };
        await service.SaveAsync(updated);

        var all = await service.GetAllAsync();
        all.Should().ContainSingle();
        all[0].Name.Should().Be("Updated");
        all[0].KeySize.Should().Be(4096);
    }

    [Fact]
    public async Task DeleteAsync_ExistingTemplate_Removes()
    {
        var service = CreateService();
        var saved = await service.SaveAsync(new CertificateTemplate
        {
            Name = "To Delete",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365
        });

        await service.DeleteAsync(saved.Id);

        var all = await service.GetAllAsync();
        all.Should().BeEmpty();
    }

    [Fact]
    public async Task DeleteAsync_PresetTemplate_DoesNotDelete()
    {
        await using var db = _dbFactory.CreateDbContext();
        db.CertificateTemplates.Add(new CertificateTemplate
        {
            Name = "Preset",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA",
            KeySize = 4096,
            ValidityDays = 3650,
            IsPreset = true
        });
        await db.SaveChangesAsync();

        var service = CreateService();
        var all = await service.GetAllAsync();
        all.Should().ContainSingle();

        await service.DeleteAsync(all[0].Id);

        var afterDelete = await service.GetAllAsync();
        afterDelete.Should().ContainSingle();
    }

    [Fact]
    public async Task GetAll_OrdersByPresetThenTypeThenName()
    {
        var service = CreateService();
        await service.SaveAsync(new CertificateTemplate
        {
            Name = "Zebra",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA", KeySize = 2048, ValidityDays = 365
        });
        await service.SaveAsync(new CertificateTemplate
        {
            Name = "Alpha",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA", KeySize = 2048, ValidityDays = 365
        });

        await using var db = _dbFactory.CreateDbContext();
        db.CertificateTemplates.Add(new CertificateTemplate
        {
            Name = "Preset Root",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA", KeySize = 4096, ValidityDays = 3650,
            IsPreset = true
        });
        await db.SaveChangesAsync();

        var all = await service.GetAllAsync();
        all.Should().HaveCount(3);
        all[0].IsPreset.Should().BeTrue();
        all[1].Name.Should().Be("Alpha");
        all[2].Name.Should().Be("Zebra");
    }
}

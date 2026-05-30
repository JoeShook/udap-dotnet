#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using Sigil.Did.Services;
using Sigil.Did.ViewModels;

namespace Sigil.Signing.Tests;

public class DidIssuanceServiceTests
{
    private readonly TestDbContextFactory _dbFactory = new();
    private readonly LocalSigningProvider _signing = new();

    private DidIssuanceService CreateService() => new(
        _dbFactory,
        [new DidKeyMethodProvider()],
        _signing,
        NullLogger<DidIssuanceService>.Instance);

    [Fact]
    public async Task IssueDidAsync_Persists_DidAndVerificationMethods()
    {
        var (trustDomainId, templateId) = await SeedAsync();
        var service = CreateService();

        var result = await service.IssueDidAsync(new DidIssuanceRequest(trustDomainId, templateId));

        result.DidDocumentId.ShouldBeGreaterThan(0);
        result.Did.ShouldStartWith("did:key:z");
        result.DidDocumentJson.ShouldContain("\"verificationMethod\"");
        result.DidDocumentJson.ShouldContain("Ed25519VerificationKey2020");
        result.DidDocumentJson.ShouldContain("\"assertionMethod\"");
        result.DidDocumentJson.ShouldContain("\"authentication\"");

        await using var db = _dbFactory.CreateDbContext();
        var persisted = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions
            .FirstAsync(db.DidDocuments, d => d.Id == result.DidDocumentId);
        persisted.Did.ShouldBe(result.Did);
        persisted.Method.ShouldBe("key");
    }

    [Fact]
    public async Task DeactivateAsync_MarksDocumentDeactivated()
    {
        var (trustDomainId, templateId) = await SeedAsync();
        var service = CreateService();
        var minted = await service.IssueDidAsync(new DidIssuanceRequest(trustDomainId, templateId));

        await service.DeactivateAsync(minted.DidDocumentId);

        var vm = await service.GetByIdAsync(minted.DidDocumentId);
        vm.ShouldNotBeNull();
        vm.Deactivated.ShouldBeTrue();
    }

    private async Task<(int TrustDomainId, int TemplateId)> SeedAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var td = new TrustDomain { Name = "test-td" };
        var tmpl = new DidTemplate
        {
            Name = "test-template",
            Method = "key",
            KeyAlgorithm = "Ed25519",
            DefaultPurposes = "assertionMethod;authentication",
        };
        db.TrustDomains.Add(td);
        db.DidTemplates.Add(tmpl);
        await db.SaveChangesAsync();
        return (td.Id, tmpl.Id);
    }
}

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
using Microsoft.Extensions.Logging;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using Sigil.Did.ViewModels;

namespace Sigil.Did.Services;

public class DidIssuanceService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly IEnumerable<IDidMethodProvider> _methodProviders;
    private readonly ISigningProvider _signingProvider;
    private readonly ILogger<DidIssuanceService> _logger;

    public DidIssuanceService(
        IDbContextFactory<SigilDbContext> dbFactory,
        IEnumerable<IDidMethodProvider> methodProviders,
        ISigningProvider signingProvider,
        ILogger<DidIssuanceService> logger)
    {
        _dbFactory = dbFactory;
        _methodProviders = methodProviders;
        _signingProvider = signingProvider;
        _logger = logger;
    }

    public async Task<DidIssuanceResult> IssueDidAsync(DidIssuanceRequest request, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var template = await db.DidTemplates.FindAsync([request.DidTemplateId], ct)
            ?? throw new InvalidOperationException($"DID template {request.DidTemplateId} not found.");

        var trustDomain = await db.TrustDomains.FindAsync([request.TrustDomainId], ct)
            ?? throw new InvalidOperationException($"Trust domain {request.TrustDomainId} not found.");

        var provider = _methodProviders.FirstOrDefault(p =>
            p.Method.Equals(template.Method, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"No registered IDidMethodProvider for method '{template.Method}'.");

        var mint = await provider.MintAsync(template, trustDomain, _signingProvider, ct);

        var didDocument = new DidDocument
        {
            TrustDomainId = trustDomain.Id,
            DidTemplateId = template.Id,
            Did = mint.Did,
            Method = mint.Method,
            CreatedAt = DateTime.UtcNow,
            VerificationMethods = mint.VerificationMethods.Select(seed => new VerificationMethod
            {
                MethodId = seed.MethodId,
                KeyAlgorithm = seed.KeyAlgorithm,
                Provider = seed.Provider,
                KeyIdentifier = seed.KeyIdentifier,
                KeySize = seed.KeySize,
                PublicKeyMultibase = seed.PublicKeyMultibase,
                Purposes = seed.Purposes,
                CreatedAt = DateTime.UtcNow,
            }).ToList()
        };

        db.DidDocuments.Add(didDocument);
        await db.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Issued DID {Did} in TrustDomain {TrustDomainId} from template {TemplateId}",
            didDocument.Did, trustDomain.Id, template.Id);

        var documentJson = DidDocumentBuilder.Build(didDocument, didDocument.VerificationMethods);

        return new DidIssuanceResult(
            DidDocumentId: didDocument.Id,
            Did: didDocument.Did,
            DidDocumentJson: documentJson);
    }

    public async Task<List<DidDocumentViewModel>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var docs = await db.DidDocuments
            .Include(d => d.TrustDomain)
            .Include(d => d.Template)
            .Include(d => d.VerificationMethods)
            .OrderByDescending(d => d.CreatedAt)
            .ToListAsync(ct);

        return docs.Select(ToViewModel).ToList();
    }

    public async Task<DidDocumentViewModel?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var doc = await db.DidDocuments
            .Include(d => d.TrustDomain)
            .Include(d => d.Template)
            .Include(d => d.VerificationMethods)
            .FirstOrDefaultAsync(d => d.Id == id, ct);

        return doc == null ? null : ToViewModel(doc);
    }

    public async Task DeactivateAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var doc = await db.DidDocuments.FindAsync([id], ct);
        if (doc == null || doc.Deactivated) return;

        doc.Deactivated = true;
        doc.DeactivatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("Deactivated DID {Did}", doc.Did);
    }

    private static DidDocumentViewModel ToViewModel(DidDocument doc) => new()
    {
        Id = doc.Id,
        Did = doc.Did,
        Method = doc.Method,
        TrustDomainId = doc.TrustDomainId,
        TrustDomainName = doc.TrustDomain?.Name ?? string.Empty,
        TemplateName = doc.Template?.Name,
        Deactivated = doc.Deactivated,
        CreatedAt = doc.CreatedAt,
        VerificationMethods = doc.VerificationMethods.Select(vm => new VerificationMethodViewModel
        {
            MethodId = vm.MethodId,
            KeyAlgorithm = vm.KeyAlgorithm,
            PublicKeyMultibase = vm.PublicKeyMultibase,
            Purposes = vm.Purposes
        }).ToList(),
        SynthesizedDocumentJson = DidDocumentBuilder.Build(doc, doc.VerificationMethods)
    };
}

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
using Sigil.Common.ViewModels;

namespace Sigil.Did.Services;

public class DidTemplateService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<DidTemplateService> _logger;

    public DidTemplateService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<DidTemplateService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<DidTemplate>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.DidTemplates
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.Method)
            .ThenBy(t => t.Name)
            .ToListAsync(ct);
    }

    public async Task<DidTemplate?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.DidTemplates.FindAsync([id], ct);
    }

    public async Task<DidTemplate> SaveAsync(DidTemplate entity, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.DidTemplates.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                db.Entry(existing).CurrentValues.SetValues(entity);
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.DidTemplates.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.DidTemplates.FindAsync([id], ct);
        if (entity != null && !entity.IsPreset)
        {
            db.DidTemplates.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<List<ImpactItem>> GetDeletionImpactAsync(int templateId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var impacts = new List<ImpactItem>();

        var count = await db.DidDocuments.CountAsync(d => d.DidTemplateId == templateId, ct);
        if (count > 0)
            impacts.Add(new ImpactItem(count, "DID document(s) reference this template", ImpactSeverity.Info));

        return impacts;
    }
}

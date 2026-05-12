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

namespace Sigil.Common.Services;

public class TemplateService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<TemplateService> _logger;

    public TemplateService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<TemplateService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<CertificateTemplate>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CertificateTemplates
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync(ct);
    }

    public async Task<CertificateTemplate> SaveAsync(CertificateTemplate entity, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.CertificateTemplates.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                db.Entry(existing).CurrentValues.SetValues(entity);
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.CertificateTemplates.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.CertificateTemplates.FindAsync([id], ct);
        if (entity != null && !entity.IsPreset)
        {
            db.CertificateTemplates.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }
}

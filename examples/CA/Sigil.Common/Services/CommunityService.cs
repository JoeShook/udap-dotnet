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

namespace Sigil.Common.Services;

public class CommunityService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CommunityService> _logger;

    public CommunityService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CommunityService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<CommunityViewModel>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        return await db.Communities
            .Select(c => new CommunityViewModel
            {
                Id = c.Id,
                Name = c.Name,
                Description = c.Description,
                BaseUrls = c.BaseUrls.OrderBy(bu => bu.SortOrder)
                    .Select(bu => new BaseUrlViewModel { Url = bu.Url, PublishingBasePath = bu.PublishingBasePath })
                    .ToList(),
                CrlValidityDays = c.CrlValidityDays,
                Enabled = c.Enabled,
                CreatedAt = c.CreatedAt,
                RootCaCount = c.CaCertificates.Count(ca => ca.ParentId == null),
                TotalCertCount = c.CaCertificates.Count()
                    + c.CaCertificates.SelectMany(ca => ca.IssuedCertificates).Count()
            })
            .OrderBy(c => c.Name)
            .ToListAsync(ct);
    }

    public async Task<Community> CreateAsync(
        string name,
        string? description,
        List<(string Url, string? PublishingBasePath)> baseUrls,
        int crlValidityDays = 7,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var community = new Community
        {
            Name = name.Trim(),
            Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            CrlValidityDays = crlValidityDays > 0 ? crlValidityDays : 7,
            Enabled = true
        };

        var sortOrder = 0;
        foreach (var (url, publishPath) in baseUrls)
        {
            if (!string.IsNullOrWhiteSpace(url))
            {
                community.BaseUrls.Add(new CommunityBaseUrl
                {
                    Url = url.Trim().TrimEnd('/'),
                    SortOrder = sortOrder++,
                    PublishingBasePath = string.IsNullOrWhiteSpace(publishPath) ? null : publishPath.Trim()
                });
            }
        }

        db.Communities.Add(community);
        await db.SaveChangesAsync(ct);
        return community;
    }

    public async Task UpdateAsync(
        int id,
        string name,
        string? description,
        List<(string Url, string? PublishingBasePath)> baseUrls,
        int crlValidityDays = 7,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.Communities
            .Include(c => c.BaseUrls)
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        if (entity == null) return;

        entity.Name = name.Trim();
        entity.Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        entity.CrlValidityDays = crlValidityDays > 0 ? crlValidityDays : 7;

        entity.BaseUrls.Clear();
        var sortOrder = 0;
        foreach (var (url, publishPath) in baseUrls)
        {
            if (!string.IsNullOrWhiteSpace(url))
            {
                entity.BaseUrls.Add(new CommunityBaseUrl
                {
                    Url = url.Trim().TrimEnd('/'),
                    SortOrder = sortOrder++,
                    PublishingBasePath = string.IsNullOrWhiteSpace(publishPath) ? null : publishPath.Trim()
                });
            }
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.Communities.FindAsync([id], ct);
        if (entity != null)
        {
            db.Communities.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }
}

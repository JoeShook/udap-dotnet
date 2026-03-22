#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Udap.CA.DbContexts;
using Udap.CA.Mappers;

namespace Udap.CA.Services;

public class CommunityService
{
    private IUdapCaContext _dbContext;
    private ILogger<CommunityService> _logger;

    public CommunityService(IUdapCaContext dbContext, ILogger<CommunityService> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    public async Task<ICollection<ViewModel.Community>> Get(CancellationToken token = default)
    {
        var communties = await _dbContext.Communities
            .Include(c => c.RootCertificates)
            .ToListAsync(cancellationToken: token);

        return communties.ToViewModels();
    }

    public async Task<ViewModel.Community> Create(ViewModel.Community community, CancellationToken token = default)
    {
        var entity = community.ToEntity();
        _dbContext.Communities.Add(entity);
        await _dbContext.SaveChangesAsync(token);

        return entity.ToViewModel();
    }

    public async Task Update(ViewModel.Community community, CancellationToken token = default)
    {
        var entity = await _dbContext.Communities
            .Where(c => c.Id == community.Id)
            .SingleOrDefaultAsync(cancellationToken: token);

        if (entity == null)
        {
            _logger.LogDebug($"No Community Id {community.Id} found in database. Update failed.");

            return;
        }

        entity.Enabled = community.Enabled;
        entity.Name = community.Name;

        await _dbContext.SaveChangesAsync(token);
    }

    public async Task<bool> Delete(int id, CancellationToken token = default)
    {
        var community = await _dbContext.Communities
            .SingleOrDefaultAsync(d => d.Id == id, token);

        if (community == null)
        {
            return false;
        }

        _dbContext.Communities.Remove(community);

        await _dbContext.SaveChangesAsync(token);

        return true;
    }
}

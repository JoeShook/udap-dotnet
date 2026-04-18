#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Microsoft.EntityFrameworkCore;
using Sigil.Common.Data;
using Sigil.Common.Services.Jobs;

namespace Sigil.UI.Components.Pages;

public partial class Jobs
{
    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private IRecurringJobScheduler JobScheduler { get; set; } = null!;
    [Inject] private CrlGenerationService CrlGenerationService { get; set; } = null!;

    private bool isLoading = true;
    private List<CrlStatusRow> crlStatuses = new();
    private Dictionary<string, List<CrlStatusRow>> crlStatusesByCommunity = new();
    private List<RecurringJobRow> recurringJobs = new();

    protected override async Task OnInitializedAsync()
    {
        LoadRecurringJobs();
        await LoadCrlStatusesAsync();
        isLoading = false;
    }

    private void LoadRecurringJobs()
    {
        var jobs = JobScheduler.GetRecurringJobs();
        recurringJobs = jobs.Select(j => new RecurringJobRow
        {
            JobId = j.JobId,
            OriginalCron = j.CronExpression,
            EditableCron = j.CronExpression,
            LastExecution = j.LastExecution,
            NextExecution = j.NextExecution
        }).ToList();
    }

    private void SaveCron(RecurringJobRow row)
    {
        JobScheduler.UpdateCronExpression(row.JobId, row.EditableCron);
        row.OriginalCron = row.EditableCron;

        // Refresh to get updated next execution time
        LoadRecurringJobs();
        StateHasChanged();
    }

    private void TriggerJob(RecurringJobRow row)
    {
        JobScheduler.TriggerJob(row.JobId);

        // Refresh to reflect the trigger
        LoadRecurringJobs();
        StateHasChanged();
    }

    private async Task GenerateCrl(CrlStatusRow row)
    {
        row.IsGenerating = true;
        StateHasChanged();

        var result = await CrlGenerationService.GenerateCrlAsync(row.CaId);

        row.IsGenerating = false;

        // Refresh the data to show the new CRL
        await LoadCrlStatusesAsync();
        StateHasChanged();
    }

    private async Task LoadCrlStatusesAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        var cas = await db.CaCertificates
            .Where(ca => !ca.IsArchived &&
                (ca.EncryptedPfxBytes != null || ca.StoreProviderHint != null))
            .Include(ca => ca.Community)
            .Include(ca => ca.Crls.Where(c => !c.IsArchived))
            .OrderBy(ca => ca.Community.Name)
            .ThenBy(ca => ca.Name)
            .ToListAsync();

        crlStatuses = cas.Select(ca =>
        {
            var latestCrl = ca.Crls
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefault();

            return new CrlStatusRow
            {
                CaId = ca.Id,
                CaName = ca.Name,
                CommunityName = ca.Community.Name,
                LatestCrlNumber = latestCrl?.CrlNumber,
                NextUpdate = latestCrl?.NextUpdate ?? DateTime.MinValue,
                HasCrl = latestCrl != null,
                NeedsRenewal = latestCrl == null
                    || latestCrl.NextUpdate <= DateTime.UtcNow.AddHours(24),
                RevokedCount = latestCrl?.Revocations?.Count ?? 0
            };
        }).ToList();

        crlStatusesByCommunity = crlStatuses
            .GroupBy(s => s.CommunityName)
            .OrderBy(g => g.Key)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    private class RecurringJobRow
    {
        public string JobId { get; init; } = string.Empty;
        public string OriginalCron { get; set; } = string.Empty;
        public string EditableCron { get; set; } = string.Empty;
        public string? LastExecution { get; init; }
        public string? NextExecution { get; init; }
    }

    private class CrlStatusRow
    {
        public int CaId { get; init; }
        public string CaName { get; init; } = string.Empty;
        public string CommunityName { get; init; } = string.Empty;
        public long? LatestCrlNumber { get; init; }
        public DateTime NextUpdate { get; init; }
        public bool HasCrl { get; init; }
        public bool NeedsRenewal { get; init; }
        public int RevokedCount { get; init; }
        public bool IsGenerating { get; set; }
    }
}

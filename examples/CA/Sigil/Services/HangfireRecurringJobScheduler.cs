#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Hangfire;
using Hangfire.Storage;
using Sigil.Common.Services.Jobs;

namespace Sigil.Services;

public class HangfireRecurringJobScheduler : IRecurringJobScheduler
{
    public List<RecurringJobInfo> GetRecurringJobs()
    {
        using var connection = JobStorage.Current.GetConnection();
        var recurringJobs = connection.GetRecurringJobs();

        return recurringJobs.Select(j => new RecurringJobInfo(
            j.Id,
            j.Cron,
            j.LastExecution?.ToString("yyyy-MM-dd HH:mm:ss UTC"),
            j.NextExecution?.ToString("yyyy-MM-dd HH:mm:ss UTC")
        )).ToList();
    }

    public void UpdateCronExpression(string jobId, string cronExpression)
    {
        using var connection = JobStorage.Current.GetConnection();
        var jobs = connection.GetRecurringJobs();
        var job = jobs.FirstOrDefault(j => j.Id == jobId);

        if (job == null)
            throw new InvalidOperationException($"Recurring job '{jobId}' not found.");

        // Re-register with the same type/method but new cron
        RecurringJob.AddOrUpdate<CrlAutoRenewalJob>(
            jobId,
            j => j.ExecuteAsync(CancellationToken.None),
            cronExpression);
    }

    public void TriggerJob(string jobId)
    {
        RecurringJob.TriggerJob(jobId);
    }

    public void RemoveJob(string jobId)
    {
        RecurringJob.RemoveIfExists(jobId);
    }
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Services.Jobs;

public record RecurringJobInfo(string JobId, string CronExpression, string? LastExecution, string? NextExecution);

/// <summary>
/// Abstraction over Hangfire's recurring job management so the UI layer
/// can read and update job schedules without depending on Hangfire directly.
/// </summary>
public interface IRecurringJobScheduler
{
    List<RecurringJobInfo> GetRecurringJobs();
    void UpdateCronExpression(string jobId, string cronExpression);
    void TriggerJob(string jobId);
    void RemoveJob(string jobId);
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Data.Entities;

public enum JobExecutionStatus : byte
{
    Running = 0,
    Succeeded = 1,
    Failed = 2
}

public class JobExecution
{
    public int Id { get; set; }

    public int JobId { get; set; }
    public Job Job { get; set; } = null!;

    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public JobExecutionStatus Status { get; set; }
    public string? ResultMessage { get; set; }
}

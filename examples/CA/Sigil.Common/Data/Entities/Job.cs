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

public enum JobType : byte
{
    CertRenewalReminder = 0,
    CrlAutoRenew = 1,
    CertificateRevocation = 2
}

public class Job
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public JobType JobType { get; set; }
    public string? CronExpression { get; set; }
    public int? TargetCertificateId { get; set; }

    /// <summary>
    /// "CaCertificate" or "IssuedCertificate".
    /// </summary>
    public string? TargetEntityType { get; set; }

    public bool Enabled { get; set; } = true;
    public DateTime? LastRunAt { get; set; }
    public DateTime? NextRunAt { get; set; }

    /// <summary>
    /// JSON blob for job-specific configuration.
    /// </summary>
    public string? Configuration { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<JobExecution> Executions { get; set; } = new List<JobExecution>();
}

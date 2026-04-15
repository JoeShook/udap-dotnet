#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Gcp.Kms;

/// <summary>
/// Configuration for connecting to GCP Cloud KMS.
/// Authentication uses Application Default Credentials (ADC) — either gcloud CLI
/// credentials or a service account key file.
/// </summary>
public class GcpKmsOptions
{
    /// <summary>
    /// GCP project ID, e.g. "my-project-123".
    /// </summary>
    public string ProjectId { get; set; } = string.Empty;

    /// <summary>
    /// GCP location for the key ring, e.g. "us-central1" or "global".
    /// </summary>
    public string LocationId { get; set; } = "us-central1";

    /// <summary>
    /// Key ring name. All Sigil-generated keys are created in this ring.
    /// </summary>
    public string KeyRingId { get; set; } = "sigil";
}

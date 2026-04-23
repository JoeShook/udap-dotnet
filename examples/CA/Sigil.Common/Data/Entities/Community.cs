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

public class Community
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>
    /// Base URL for the certificate/CRL distribution server (e.g., "http://host.docker.internal:5033").
    /// Used to expand {BaseUrl} tokens in certificate template CDP and AIA URL patterns.
    /// </summary>
    public string? BaseUrl { get; set; }

    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<CaCertificate> CaCertificates { get; set; } = new List<CaCertificate>();
}

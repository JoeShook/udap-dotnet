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

public class IssuedCertificate
{
    public int Id { get; set; }

    public int IssuingCaCertificateId { get; set; }
    public CaCertificate IssuingCaCertificate { get; set; } = null!;

    public int? TemplateId { get; set; }
    public CertificateTemplate? Template { get; set; }

    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string? SubjectAltNames { get; set; }
    public string X509CertificatePem { get; set; } = string.Empty;
    public byte[]? EncryptedPfxBytes { get; set; }
    public string? PfxPassword { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 2048;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public bool Enabled { get; set; } = true;
    public bool IsArchived { get; set; }
    public DateTime? ArchivedAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

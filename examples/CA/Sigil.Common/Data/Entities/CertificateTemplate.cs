using System.Security.Cryptography.X509Certificates;

namespace Sigil.Common.Data.Entities;

public enum CertificateType : byte
{
    RootCa = 0,
    IntermediateCa = 1,
    EndEntityClient = 2,
    EndEntityServer = 3
}

public class CertificateTemplate
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public CertificateType CertificateType { get; set; }
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 2048;
    public int ValidityDays { get; set; } = 365;
    public int KeyUsageFlags { get; set; } = (int)X509KeyUsageFlags.DigitalSignature;
    public bool IsKeyUsageCritical { get; set; } = true;

    /// <summary>
    /// Semicolon-delimited OIDs (e.g., "1.3.6.1.5.5.7.3.2;1.3.6.1.5.5.7.3.1").
    /// </summary>
    public string? ExtendedKeyUsageOids { get; set; }

    public bool IsBasicConstraintsCa { get; set; }
    public string? SubjectTemplate { get; set; }
    public bool IncludeCdp { get; set; }
    public bool IncludeAia { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new List<IssuedCertificate>();
}

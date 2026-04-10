namespace Sigil.Common.Data.Entities;

public class Crl
{
    public int Id { get; set; }

    /// <summary>
    /// The CA that issued this CRL.
    /// </summary>
    public int CaCertificateId { get; set; }
    public CaCertificate CaCertificate { get; set; } = null!;

    /// <summary>
    /// CRL number from the CRL Number extension (2.5.29.20).
    /// </summary>
    public long CrlNumber { get; set; }

    /// <summary>
    /// When this CRL was issued.
    /// </summary>
    public DateTime ThisUpdate { get; set; }

    /// <summary>
    /// When the next CRL is expected. Drives job scheduling.
    /// </summary>
    public DateTime NextUpdate { get; set; }

    /// <summary>
    /// Signature algorithm used to sign the CRL.
    /// </summary>
    public string SignatureAlgorithm { get; set; } = string.Empty;

    /// <summary>
    /// The raw DER-encoded CRL bytes.
    /// </summary>
    public byte[] RawBytes { get; set; } = [];

    /// <summary>
    /// Original file name (for display/reference).
    /// </summary>
    public string? FileName { get; set; }

    /// <summary>
    /// Whether the CRL signature was validated against the issuing CA.
    /// </summary>
    public bool SignatureValid { get; set; }

    public DateTime ImportedAt { get; set; } = DateTime.UtcNow;

    public ICollection<CertificateRevocation> Revocations { get; set; } = new List<CertificateRevocation>();
}

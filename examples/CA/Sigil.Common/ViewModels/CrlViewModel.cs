#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.ViewModels;

public class CrlViewModel
{
    public int Id { get; set; }
    public int CaCertificateId { get; set; }
    public string CaName { get; set; } = string.Empty;
    public long CrlNumber { get; set; }
    public DateTime ThisUpdate { get; set; }
    public DateTime NextUpdate { get; set; }
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public bool SignatureValid { get; set; }
    public string? FileName { get; set; }
    public int RevokedCount { get; set; }
    public DateTime ImportedAt { get; set; }

    public CrlTimeStatus TimeStatus
    {
        get
        {
            if (DateTime.UtcNow > NextUpdate) return CrlTimeStatus.Expired;
            if (DateTime.UtcNow > NextUpdate.AddDays(-7)) return CrlTimeStatus.ExpiringSoon;
            return CrlTimeStatus.Valid;
        }
    }

    public List<RevokedCertEntry> RevokedCertificates { get; set; } = new();
}

public enum CrlTimeStatus
{
    Valid,
    ExpiringSoon,
    Expired
}

public class RevokedCertEntry
{
    public string SerialNumber { get; set; } = string.Empty;
    public string? Thumbprint { get; set; }
    public DateTime RevocationDate { get; set; }
    public int ReasonCode { get; set; }

    public string ReasonName => ReasonCode switch
    {
        0 => "Unspecified",
        1 => "Key Compromise",
        2 => "CA Compromise",
        3 => "Affiliation Changed",
        4 => "Superseded",
        5 => "Cessation of Operation",
        6 => "Certificate Hold",
        9 => "Privilege Withdrawn",
        10 => "AA Compromise",
        _ => $"Unknown ({ReasonCode})"
    };
}

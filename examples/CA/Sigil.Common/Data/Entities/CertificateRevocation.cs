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

public class CertificateRevocation
{
    public int Id { get; set; }

    /// <summary>
    /// The CRL this revocation entry came from.
    /// </summary>
    public int CrlId { get; set; }
    public Crl Crl { get; set; } = null!;

    public string RevokedCertSerialNumber { get; set; } = string.Empty;
    public string? RevokedCertThumbprint { get; set; }
    public DateTime RevocationDate { get; set; }

    /// <summary>
    /// CRL reason code (0=Unspecified, 1=KeyCompromise, 2=CACompromise,
    /// 3=AffiliationChanged, 4=Superseded, 5=CessationOfOperation,
    /// 6=CertificateHold, 9=PrivilegeWithdrawn, 10=AACompromise).
    /// </summary>
    public int RevocationReason { get; set; }
}

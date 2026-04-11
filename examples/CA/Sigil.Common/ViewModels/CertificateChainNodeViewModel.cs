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

public class CertificateChainNodeViewModel
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotAfter { get; set; }
    public CertificateStatus Status { get; set; }

    /// <summary>
    /// "RootCA", "IntermediateCA", "EndEntity", or "CRL".
    /// </summary>
    public string CertificateRole { get; set; } = string.Empty;

    /// <summary>
    /// Entity type for navigation: "CaCertificate", "IssuedCertificate", or "Crl".
    /// </summary>
    public string EntityType { get; set; } = string.Empty;

    public List<CertificateChainNodeViewModel> Children { get; set; } = new();
}

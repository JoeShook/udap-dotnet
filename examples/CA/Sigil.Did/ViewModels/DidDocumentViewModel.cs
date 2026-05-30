#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Did.ViewModels;

public class DidDocumentViewModel
{
    public int Id { get; set; }
    public string Did { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public int TrustDomainId { get; set; }
    public string TrustDomainName { get; set; } = string.Empty;
    public string? TemplateName { get; set; }
    public bool Deactivated { get; set; }
    public DateTime CreatedAt { get; set; }
    public IReadOnlyList<VerificationMethodViewModel> VerificationMethods { get; set; } = [];
    public string SynthesizedDocumentJson { get; set; } = string.Empty;
}

public class VerificationMethodViewModel
{
    public string MethodId { get; set; } = string.Empty;
    public string KeyAlgorithm { get; set; } = string.Empty;
    public string PublicKeyMultibase { get; set; } = string.Empty;
    public string Purposes { get; set; } = string.Empty;
}

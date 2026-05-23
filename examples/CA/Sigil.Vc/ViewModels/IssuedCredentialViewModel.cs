#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Vc.ViewModels;

public class IssuedCredentialViewModel
{
    public int Id { get; set; }
    public int TrustDomainId { get; set; }
    public string TrustDomainName { get; set; } = string.Empty;
    public string CredentialId { get; set; } = string.Empty;
    public string SubjectDid { get; set; } = string.Empty;
    public string IssuerDid { get; set; } = string.Empty;
    public string SchemaName { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public string SignedCredential { get; set; } = string.Empty;
    public string DecodedHeaderJson { get; set; } = string.Empty;
    public string DecodedPayloadJson { get; set; } = string.Empty;
    public string ClaimsJson { get; set; } = string.Empty;
    public DateTime IssuedAt { get; set; }
    public DateTime? ValidUntil { get; set; }
    public bool Revoked { get; set; }
    public DateTime? RevokedAt { get; set; }
}

public record CredentialVerifyResult(
    bool Valid,
    string? Message,
    string? DecodedHeaderJson,
    string? DecodedPayloadJson);

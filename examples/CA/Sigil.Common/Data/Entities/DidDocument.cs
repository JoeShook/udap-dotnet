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

public class DidDocument
{
    public int Id { get; set; }
    public int TrustDomainId { get; set; }
    public TrustDomain TrustDomain { get; set; } = null!;

    public int? DidTemplateId { get; set; }
    public DidTemplate? Template { get; set; }

    /// <summary>The full DID string, e.g. "did:key:z6Mk...".</summary>
    public string Did { get; set; } = string.Empty;

    /// <summary>DID method name, e.g. "key", "web", "jwk".</summary>
    public string Method { get; set; } = string.Empty;

    public bool Deactivated { get; set; }
    public DateTime? DeactivatedAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<VerificationMethod> VerificationMethods { get; set; } = new List<VerificationMethod>();
    public ICollection<IssuedCredential> IssuedCredentials { get; set; } = new List<IssuedCredential>();
}

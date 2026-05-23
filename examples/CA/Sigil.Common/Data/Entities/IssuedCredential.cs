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

public class IssuedCredential
{
    public int Id { get; set; }

    public int TrustDomainId { get; set; }
    public TrustDomain TrustDomain { get; set; } = null!;

    public int CredentialSchemaId { get; set; }
    public CredentialSchema Schema { get; set; } = null!;

    public int IssuerDidDocumentId { get; set; }
    public DidDocument IssuerDid { get; set; } = null!;

    /// <summary>Subject DID as a string. Subject may not be a DID Sigil controls.</summary>
    public string SubjectDid { get; set; } = string.Empty;

    /// <summary>Submitted claims as JSON (validated against schema at issuance).</summary>
    public string ClaimsJson { get; set; } = "{}";

    /// <summary>Securing format used: "jwt_vc" for Phase D.</summary>
    public string Format { get; set; } = "jwt_vc";

    /// <summary>The full signed credential (e.g. compact JWT for jwt_vc).</summary>
    public string SignedCredential { get; set; } = string.Empty;

    /// <summary>VC `id` field: URN-style identifier (e.g. "urn:uuid:...").</summary>
    public string CredentialId { get; set; } = string.Empty;

    public DateTime IssuedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ValidUntil { get; set; }

    // Phase E will replace with credentialStatus pointing to a Bitstring Status List entry.
    public bool Revoked { get; set; }
    public DateTime? RevokedAt { get; set; }
}

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

public class DidTemplate
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>DID method: "key" (Phase A), "web" (Phase B), "jwk", etc.</summary>
    public string Method { get; set; } = "key";

    /// <summary>"Ed25519" (default for did:key), "ECDSA" (future).</summary>
    public string KeyAlgorithm { get; set; } = "Ed25519";

    /// <summary>"nistP256", "nistP384", "nistP521". Only used when KeyAlgorithm is "ECDSA".</summary>
    public string? EcdsaCurve { get; set; }

    /// <summary>Semicolon-delimited DID Document key purposes: "assertionMethod;authentication".</summary>
    public string DefaultPurposes { get; set; } = "assertionMethod;authentication";

    public bool IsPreset { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<DidDocument> DidDocuments { get; set; } = new List<DidDocument>();
}

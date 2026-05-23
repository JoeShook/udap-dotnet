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

public class VerificationMethod
{
    public int Id { get; set; }
    public int DidDocumentId { get; set; }
    public DidDocument DidDocument { get; set; } = null!;

    /// <summary>Full verification method id including fragment, e.g. "did:key:z6Mk...#z6Mk...".</summary>
    public string MethodId { get; set; } = string.Empty;

    /// <summary>"Ed25519", "ECDSA", "RSA".</summary>
    public string KeyAlgorithm { get; set; } = "Ed25519";

    // Mirror of SigningKeyReference — DID code uses ISigningProvider to sign/verify.
    public string Provider { get; set; } = "local";
    public string KeyIdentifier { get; set; } = string.Empty;
    public int KeySize { get; set; }

    /// <summary>Multibase-encoded public key (z-prefix base58btc).</summary>
    public string PublicKeyMultibase { get; set; } = string.Empty;

    /// <summary>Semicolon-delimited purposes: "assertionMethod;authentication".</summary>
    public string Purposes { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

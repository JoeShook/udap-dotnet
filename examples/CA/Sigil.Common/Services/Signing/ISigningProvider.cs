#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Abstraction for certificate signing operations. Implementations may use local keys (PFX)
/// or remote signing services (Vault Transit, Cloud KMS) where private keys never leave
/// the provider boundary.
/// </summary>
public interface ISigningProvider
{
    /// <summary>
    /// The provider name, e.g. "local" or "vault-transit".
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Signs data using the referenced key.
    /// For local: signs with the in-memory private key.
    /// For Vault Transit: calls the Transit sign API.
    /// </summary>
    Task<byte[]> SignDataAsync(byte[] data, HashAlgorithmName hashAlgorithm,
        SigningKeyReference keyRef, CancellationToken ct = default);

    /// <summary>
    /// Gets the public key for the referenced key.
    /// Used to build CertificateRequest with the correct public key before signing.
    /// </summary>
    Task<AsymmetricAlgorithm> GetPublicKeyAsync(SigningKeyReference keyRef,
        CancellationToken ct = default);

    /// <summary>
    /// Generates a new key pair and returns a reference to it.
    /// For local: creates RSA/ECDSA in memory.
    /// For Vault: creates a new Transit key.
    /// </summary>
    Task<SigningKeyReference> GenerateKeyAsync(string keyAlgorithm, int keySize,
        string? ecdsaCurve = null, CancellationToken ct = default);
}

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
    /// Note: when the key is Ed25519, <paramref name="hashAlgorithm"/> is ignored (EdDSA hashes internally).
    /// </summary>
    Task<byte[]> SignDataAsync(byte[] data, HashAlgorithmName hashAlgorithm,
        SigningKeyReference keyRef, CancellationToken ct = default);

    /// <summary>
    /// Gets the public key for the referenced key as an <see cref="AsymmetricAlgorithm"/> for use
    /// with <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/>.
    /// Throws <see cref="NotSupportedException"/> for keys that have no <c>AsymmetricAlgorithm</c>
    /// representation in .NET (e.g. Ed25519). For those, use <see cref="GetRawPublicKeyAsync"/>.
    /// </summary>
    Task<AsymmetricAlgorithm> GetPublicKeyAsync(SigningKeyReference keyRef,
        CancellationToken ct = default);

    /// <summary>
    /// Gets the raw public key bytes for the referenced key. Used by DID code that needs
    /// raw key material (e.g. did:key multicodec/multibase encoding). Algorithm-specific:
    /// Ed25519 returns 32 raw bytes; RSA/ECDSA return DER-encoded SubjectPublicKeyInfo.
    /// </summary>
    Task<RawPublicKey> GetRawPublicKeyAsync(SigningKeyReference keyRef,
        CancellationToken ct = default);

    /// <summary>
    /// Generates a new key pair and returns a reference to it.
    /// Supported algorithms: "RSA", "ECDSA", "Ed25519" (local provider only in Phase A).
    /// For Ed25519, <paramref name="keySize"/> is ignored (always 256).
    /// </summary>
    Task<SigningKeyReference> GenerateKeyAsync(string keyAlgorithm, int keySize,
        string? ecdsaCurve = null, CancellationToken ct = default);
}

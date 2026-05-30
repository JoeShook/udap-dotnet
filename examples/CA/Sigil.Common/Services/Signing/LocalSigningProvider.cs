#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Local signing provider that generates and holds keys in memory.
/// RSA / ECDSA use .NET primitives; Ed25519 uses BouncyCastle (no .NET native type).
/// </summary>
public sealed class LocalSigningProvider : ISigningProvider, IDisposable
{
    public string ProviderName => "local";

    // Holds either AsymmetricAlgorithm (RSA/ECDSA) or AsymmetricCipherKeyPair (Ed25519, BC).
    private readonly ConcurrentDictionary<string, object> _keys = new();

    public Task<SigningKeyReference> GenerateKeyAsync(
        string keyAlgorithm, int keySize, string? ecdsaCurve = null,
        CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");

        if (keyAlgorithm.Equals("Ed25519", StringComparison.OrdinalIgnoreCase))
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            _keys[id] = pair;
            return Task.FromResult(new SigningKeyReference("local", id, "Ed25519", 256));
        }

        AsymmetricAlgorithm key;
        if (keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = ecdsaCurve?.ToLowerInvariant() switch
            {
                "nistp256" => ECCurve.NamedCurves.nistP256,
                "nistp384" => ECCurve.NamedCurves.nistP384,
                "nistp521" => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP384
            };
            key = ECDsa.Create(curve);
            keySize = ((ECDsa)key).KeySize;
        }
        else
        {
            key = RSA.Create(keySize);
        }

        _keys[id] = key;

        return Task.FromResult(new SigningKeyReference("local", id, keyAlgorithm, keySize));
    }

    public Task<AsymmetricAlgorithm> GetPublicKeyAsync(
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        if (!_keys.TryGetValue(keyRef.KeyIdentifier, out var entry))
            throw new InvalidOperationException($"Local key '{keyRef.KeyIdentifier}' not found.");

        if (entry is AsymmetricAlgorithm asym)
            return Task.FromResult(asym);

        throw new NotSupportedException(
            $"Key '{keyRef.KeyIdentifier}' (algorithm: {keyRef.KeyAlgorithm}) has no AsymmetricAlgorithm representation. " +
            "Use GetRawPublicKeyAsync for Ed25519.");
    }

    public Task<RawPublicKey> GetRawPublicKeyAsync(
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        if (!_keys.TryGetValue(keyRef.KeyIdentifier, out var entry))
            throw new InvalidOperationException($"Local key '{keyRef.KeyIdentifier}' not found.");

        return entry switch
        {
            AsymmetricCipherKeyPair pair when pair.Public is Ed25519PublicKeyParameters edPub
                => Task.FromResult(new RawPublicKey("Ed25519", edPub.GetEncoded())),
            RSA rsa
                => Task.FromResult(new RawPublicKey("RSA", rsa.ExportSubjectPublicKeyInfo())),
            ECDsa ec
                => Task.FromResult(new RawPublicKey("ECDSA", ec.ExportSubjectPublicKeyInfo())),
            _ => throw new NotSupportedException(
                $"Unsupported key type for '{keyRef.KeyIdentifier}': {entry.GetType().Name}")
        };
    }

    public Task<byte[]> SignDataAsync(
        byte[] data, HashAlgorithmName hashAlgorithm,
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        if (!_keys.TryGetValue(keyRef.KeyIdentifier, out var entry))
            throw new InvalidOperationException($"Local key '{keyRef.KeyIdentifier}' not found.");

        byte[] signature;
        if (entry is AsymmetricCipherKeyPair pair && pair.Private is Ed25519PrivateKeyParameters edPriv)
        {
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, edPriv);
            signer.BlockUpdate(data, 0, data.Length);
            signature = signer.GenerateSignature();
        }
        else if (entry is ECDsa ecdsa)
        {
            signature = ecdsa.SignData(data, hashAlgorithm);
        }
        else if (entry is RSA rsa)
        {
            signature = rsa.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type: {entry.GetType().Name}");
        }

        return Task.FromResult(signature);
    }

    /// <summary>
    /// Gets the raw asymmetric algorithm for direct use by CertificateRequest (local path only).
    /// Only valid for RSA / ECDSA keys — Ed25519 has no CertificateRequest path.
    /// </summary>
    internal AsymmetricAlgorithm GetKeyDirect(string keyIdentifier)
    {
        if (!_keys.TryGetValue(keyIdentifier, out var entry))
            throw new InvalidOperationException($"Local key '{keyIdentifier}' not found.");
        if (entry is AsymmetricAlgorithm asym)
            return asym;
        throw new InvalidOperationException(
            $"Key '{keyIdentifier}' is not an AsymmetricAlgorithm (type: {entry.GetType().Name}). " +
            "X.509 cert flow does not support this key type.");
    }

    /// <summary>
    /// Removes a key from the in-memory store after certificate generation is complete.
    /// </summary>
    internal void ReleaseKey(string keyIdentifier)
    {
        if (_keys.TryRemove(keyIdentifier, out var entry) && entry is IDisposable disp)
            disp.Dispose();
    }

    public void Dispose()
    {
        foreach (var entry in _keys.Values)
        {
            if (entry is IDisposable disp)
                disp.Dispose();
        }
        _keys.Clear();
    }
}

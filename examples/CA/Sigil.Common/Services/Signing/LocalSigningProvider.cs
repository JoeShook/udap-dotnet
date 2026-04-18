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

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Local signing provider that generates and holds keys in memory.
/// This is the default provider — same behavior as the original CertificateIssuanceService.
/// </summary>
public sealed class LocalSigningProvider : ISigningProvider, IDisposable
{
    public string ProviderName => "local";

    private readonly ConcurrentDictionary<string, AsymmetricAlgorithm> _keys = new();

    public Task<SigningKeyReference> GenerateKeyAsync(
        string keyAlgorithm, int keySize, string? ecdsaCurve = null,
        CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
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
        if (!_keys.TryGetValue(keyRef.KeyIdentifier, out var key))
            throw new InvalidOperationException($"Local key '{keyRef.KeyIdentifier}' not found.");

        return Task.FromResult(key);
    }

    public Task<byte[]> SignDataAsync(
        byte[] data, HashAlgorithmName hashAlgorithm,
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        if (!_keys.TryGetValue(keyRef.KeyIdentifier, out var key))
            throw new InvalidOperationException($"Local key '{keyRef.KeyIdentifier}' not found.");

        byte[] signature;
        if (key is ECDsa ecdsa)
        {
            signature = ecdsa.SignData(data, hashAlgorithm);
        }
        else if (key is RSA rsa)
        {
            signature = rsa.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type: {key.GetType().Name}");
        }

        return Task.FromResult(signature);
    }

    /// <summary>
    /// Gets the raw asymmetric algorithm for direct use by CertificateRequest (local path only).
    /// </summary>
    internal AsymmetricAlgorithm GetKeyDirect(string keyIdentifier)
    {
        if (!_keys.TryGetValue(keyIdentifier, out var key))
            throw new InvalidOperationException($"Local key '{keyIdentifier}' not found.");
        return key;
    }

    /// <summary>
    /// Removes a key from the in-memory store after certificate generation is complete.
    /// </summary>
    internal void ReleaseKey(string keyIdentifier)
    {
        if (_keys.TryRemove(keyIdentifier, out var key))
            key.Dispose();
    }

    public void Dispose()
    {
        foreach (var key in _keys.Values)
            key.Dispose();
        _keys.Clear();
    }
}

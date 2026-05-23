#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using SimpleBase;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;

namespace Sigil.Did.Services;

/// <summary>
/// Implements the did:key method (https://w3c-ccg.github.io/did-key-spec/).
/// The DID is the public key encoded with multicodec + multibase. Phase A: Ed25519 only.
/// </summary>
public sealed class DidKeyMethodProvider : IDidMethodProvider
{
    public string Method => "key";

    // Multicodec prefix for ed25519-pub (0xED) as unsigned varint = [0xED, 0x01].
    private static readonly byte[] Ed25519MulticodecPrefix = [0xED, 0x01];

    public async Task<DidMintResult> MintAsync(
        DidTemplate template,
        TrustDomain trustDomain,
        ISigningProvider signingProvider,
        CancellationToken ct = default)
    {
        if (!template.KeyAlgorithm.Equals("Ed25519", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException(
                $"did:key Phase A supports Ed25519 only. Template requested: {template.KeyAlgorithm}.");
        }

        var keyRef = await signingProvider.GenerateKeyAsync("Ed25519", 0, ct: ct);
        var rawKey = await signingProvider.GetRawPublicKeyAsync(keyRef, ct);

        if (!rawKey.Algorithm.Equals("Ed25519", StringComparison.OrdinalIgnoreCase) || rawKey.Bytes.Length != 32)
        {
            throw new InvalidOperationException(
                $"Expected 32-byte Ed25519 public key, got {rawKey.Algorithm} with {rawKey.Bytes.Length} bytes.");
        }

        var multibase = EncodeMultibase(Ed25519MulticodecPrefix, rawKey.Bytes);
        var did = $"did:key:{multibase}";
        var methodId = $"{did}#{multibase}";

        var seed = new VerificationMethodSeed(
            MethodId: methodId,
            KeyAlgorithm: "Ed25519",
            Provider: keyRef.Provider,
            KeyIdentifier: keyRef.KeyIdentifier,
            KeySize: keyRef.KeySize,
            PublicKeyMultibase: multibase,
            Purposes: template.DefaultPurposes);

        return new DidMintResult(did, Method, [seed]);
    }

    /// <summary>
    /// Encodes multicodec prefix + raw key bytes as multibase base58btc with 'z' prefix.
    /// </summary>
    private static string EncodeMultibase(byte[] multicodecPrefix, byte[] keyBytes)
    {
        var buffer = new byte[multicodecPrefix.Length + keyBytes.Length];
        Buffer.BlockCopy(multicodecPrefix, 0, buffer, 0, multicodecPrefix.Length);
        Buffer.BlockCopy(keyBytes, 0, buffer, multicodecPrefix.Length, keyBytes.Length);
        return "z" + Base58.Bitcoin.Encode(buffer);
    }

    /// <summary>
    /// Decodes a did:key multibase identifier (e.g. "z6Mk...") back to (multicodec, rawKey).
    /// Exposed for tests and resolver scenarios.
    /// </summary>
    public static (byte[] Multicodec, byte[] RawKey) DecodeMultibase(string multibase)
    {
        if (string.IsNullOrEmpty(multibase) || multibase[0] != 'z')
            throw new ArgumentException("Multibase value must start with 'z' (base58btc).", nameof(multibase));

        var decoded = Base58.Bitcoin.Decode(multibase.AsSpan(1)).ToArray();

        // Phase A: only Ed25519 (2-byte prefix). Future methods would need varint parsing.
        if (decoded.Length < 3)
            throw new FormatException("Multibase payload too short.");

        var multicodec = new[] { decoded[0], decoded[1] };
        var rawKey = decoded[2..];
        return (multicodec, rawKey);
    }
}

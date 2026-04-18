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
using Google.Api.Gax.ResourceNames;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sigil.Common.Services.Signing;

namespace Sigil.Gcp.Kms;

/// <summary>
/// Signing provider that delegates to Google Cloud KMS.
/// Private keys never leave Cloud HSM/KMS — only the signature is returned.
/// Authentication uses Application Default Credentials (gcloud CLI or service account).
/// </summary>
public sealed class GcpKmsSigningProvider : ISigningProvider
{
    public string ProviderName => "gcp-kms";

    private readonly GcpKmsOptions _options;
    private readonly ILogger<GcpKmsSigningProvider> _logger;
    private readonly Lazy<KeyManagementServiceClient> _client;

    public GcpKmsSigningProvider(
        IOptions<GcpKmsOptions> options,
        ILogger<GcpKmsSigningProvider> logger)
    {
        _options = options.Value;
        _logger = logger;
        // Lazy-init so the provider can be registered even when GCP isn't configured
        _client = new Lazy<KeyManagementServiceClient>(() => KeyManagementServiceClient.Create());
    }

    public async Task<SigningKeyReference> GenerateKeyAsync(
        string keyAlgorithm, int keySize, string? ecdsaCurve = null,
        CancellationToken ct = default)
    {
        var client = _client.Value;
        var keyRingName = new KeyRingName(_options.ProjectId, _options.LocationId, _options.KeyRingId);

        // Ensure the key ring exists (CreateKeyRing is idempotent-ish; catch AlreadyExists)
        await EnsureKeyRingAsync(client, keyRingName, ct);

        var cryptoKeyId = $"sigil-{Guid.NewGuid():N}";
        var algorithm = MapToKmsAlgorithm(keyAlgorithm, keySize, ecdsaCurve);

        var cryptoKey = new CryptoKey
        {
            Purpose = CryptoKey.Types.CryptoKeyPurpose.AsymmetricSign,
            VersionTemplate = new CryptoKeyVersionTemplate
            {
                Algorithm = algorithm
            }
        };

        var created = await client.CreateCryptoKeyAsync(keyRingName, cryptoKeyId, cryptoKey, ct);

        _logger.LogInformation(
            "Created GCP KMS key '{KeyId}' (algorithm: {Algorithm}) in {KeyRing}",
            cryptoKeyId, algorithm, keyRingName);

        return new SigningKeyReference("gcp-kms", cryptoKeyId, keyAlgorithm, keySize);
    }

    public async Task<AsymmetricAlgorithm> GetPublicKeyAsync(
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        var client = _client.Value;
        var versionName = BuildKeyVersionName(keyRef.KeyIdentifier);

        // Wait for the key version to be enabled (newly created keys may take a moment)
        await WaitForKeyVersionAsync(client, versionName, ct);

        var publicKey = await client.GetPublicKeyAsync(versionName, ct);
        var pem = publicKey.Pem;

        if (keyRef.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return ecdsa;
        }
        else
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
    }

    public async Task<byte[]> SignDataAsync(
        byte[] data, HashAlgorithmName hashAlgorithm,
        SigningKeyReference keyRef, CancellationToken ct = default)
    {
        var client = _client.Value;
        var versionName = BuildKeyVersionName(keyRef.KeyIdentifier);

        // GCP KMS AsymmetricSign expects a pre-computed digest
        var digest = ComputeDigest(data, hashAlgorithm);

        var response = await client.AsymmetricSignAsync(versionName, digest, ct);
        var signatureBytes = response.Signature.ToByteArray();

        // GCP KMS returns ECDSA signatures in DER format — same as BouncyCastle expects.
        // No format conversion needed (unlike Vault Transit which returns P1363).

        _logger.LogDebug("Signed {Bytes} bytes with GCP KMS key '{KeyId}'",
            data.Length, keyRef.KeyIdentifier);

        return signatureBytes;
    }

    /// <summary>
    /// Destroys the primary key version, making the key unusable for signing.
    /// The key metadata remains in KMS for audit purposes.
    /// </summary>
    public async Task DestroyKeyVersionAsync(string keyId, CancellationToken ct = default)
    {
        var client = _client.Value;
        var versionName = BuildKeyVersionName(keyId);

        var destroyed = await client.DestroyCryptoKeyVersionAsync(versionName, ct);
        _logger.LogInformation("Destroyed GCP KMS key version '{KeyVersion}' (state: {State})",
            versionName, destroyed.State);
    }

    private CryptoKeyVersionName BuildKeyVersionName(string keyId)
    {
        return new CryptoKeyVersionName(
            _options.ProjectId,
            _options.LocationId,
            _options.KeyRingId,
            keyId,
            "1"); // Primary version
    }

    private async Task EnsureKeyRingAsync(
        KeyManagementServiceClient client, KeyRingName keyRingName, CancellationToken ct)
    {
        try
        {
            await client.GetKeyRingAsync(keyRingName, ct);
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.NotFound)
        {
            var locationName = new LocationName(_options.ProjectId, _options.LocationId);
            await client.CreateKeyRingAsync(locationName, keyRingName.KeyRingId, new KeyRing(), ct);
            _logger.LogInformation("Created GCP KMS key ring '{KeyRing}'", keyRingName);
        }
    }

    private static async Task WaitForKeyVersionAsync(
        KeyManagementServiceClient client, CryptoKeyVersionName versionName, CancellationToken ct)
    {
        // Newly created keys may not be immediately ENABLED; poll briefly
        for (int i = 0; i < 10; i++)
        {
            var version = await client.GetCryptoKeyVersionAsync(versionName, ct);
            if (version.State == CryptoKeyVersion.Types.CryptoKeyVersionState.Enabled)
                return;

            await Task.Delay(500, ct);
        }

        throw new InvalidOperationException(
            $"GCP KMS key version '{versionName}' did not reach ENABLED state within timeout.");
    }

    private static Digest ComputeDigest(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        var digest = new Digest();
        var name = hashAlgorithm.Name ?? "SHA256";

        if (name.Equals("SHA256", StringComparison.OrdinalIgnoreCase))
        {
            digest.Sha256 = ByteString.CopyFrom(SHA256.HashData(data));
        }
        else if (name.Equals("SHA384", StringComparison.OrdinalIgnoreCase))
        {
            digest.Sha384 = ByteString.CopyFrom(SHA384.HashData(data));
        }
        else if (name.Equals("SHA512", StringComparison.OrdinalIgnoreCase))
        {
            digest.Sha512 = ByteString.CopyFrom(SHA512.HashData(data));
        }
        else
        {
            throw new NotSupportedException($"Hash algorithm '{name}' is not supported by GCP KMS.");
        }

        return digest;
    }

    private static CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm MapToKmsAlgorithm(
        string keyAlgorithm, int keySize, string? ecdsaCurve)
    {
        if (keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            return ecdsaCurve?.ToLowerInvariant() switch
            {
                "nistp256" => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256,
                "nistp384" => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384,
                _ => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384
            };
        }

        return keySize switch
        {
            2048 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs12048Sha256,
            3072 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs13072Sha256,
            4096 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs14096Sha256,
            _ => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs14096Sha256
        };
    }
}

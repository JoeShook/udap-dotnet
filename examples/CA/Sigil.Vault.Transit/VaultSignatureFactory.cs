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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Sigil.Common.Services.Signing;

namespace Sigil.Vault.Transit;

/// <summary>
/// BouncyCastle ISignatureFactory that delegates signing to an ISigningProvider.
/// Used with X509V3CertificateGenerator for remote signing (Vault Transit, Cloud KMS).
/// </summary>
internal sealed class VaultSignatureFactory : ISignatureFactory
{
    private readonly ISigningProvider _provider;
    private readonly SigningKeyReference _keyRef;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly AlgorithmIdentifier _algId;

    public VaultSignatureFactory(
        ISigningProvider provider,
        SigningKeyReference keyRef,
        HashAlgorithmName hashAlgorithm)
    {
        _provider = provider;
        _keyRef = keyRef;
        _hashAlgorithm = hashAlgorithm;
        _algId = BuildAlgorithmIdentifier(keyRef.KeyAlgorithm, hashAlgorithm);
    }

    public object AlgorithmDetails => _algId;

    public IStreamCalculator<IBlockResult> CreateCalculator()
    {
        return new VaultStreamCalculator(_provider, _keyRef, _hashAlgorithm);
    }

    private static AlgorithmIdentifier BuildAlgorithmIdentifier(
        string keyAlgorithm, HashAlgorithmName hashAlgorithm)
    {
        // Map to X.509 signature algorithm OIDs
        if (keyAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase))
        {
            var oid = hashAlgorithm.Name switch
            {
                "SHA384" => Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha384WithRsaEncryption,
                "SHA512" => Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha512WithRsaEncryption,
                _ => Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha256WithRsaEncryption
            };
            return new AlgorithmIdentifier(oid, DerNull.Instance);
        }
        else // ECDSA
        {
            var oid = hashAlgorithm.Name switch
            {
                "SHA384" => X9ObjectIdentifiers.ECDsaWithSha384,
                "SHA512" => X9ObjectIdentifiers.ECDsaWithSha512,
                _ => X9ObjectIdentifiers.ECDsaWithSha256
            };
            return new AlgorithmIdentifier(oid);
        }
    }

    /// <summary>
    /// Stream calculator that buffers all TBS data and signs it via the provider when GetResult() is called.
    /// Note: GetResult() blocks on async — this is unavoidable because BouncyCastle's API is synchronous.
    /// </summary>
    private sealed class VaultStreamCalculator : IStreamCalculator<IBlockResult>
    {
        private readonly ISigningProvider _provider;
        private readonly SigningKeyReference _keyRef;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly MemoryStream _buffer = new();

        public VaultStreamCalculator(
            ISigningProvider provider,
            SigningKeyReference keyRef,
            HashAlgorithmName hashAlgorithm)
        {
            _provider = provider;
            _keyRef = keyRef;
            _hashAlgorithm = hashAlgorithm;
        }

        public Stream Stream => _buffer;

        public IBlockResult GetResult()
        {
            var data = _buffer.ToArray();
            // Block on async — BouncyCastle doesn't support async signing
            var signature = _provider.SignDataAsync(data, _hashAlgorithm, _keyRef)
                .GetAwaiter().GetResult();
            return new SimpleBlockResult(signature);
        }
    }

    private sealed class SimpleBlockResult : IBlockResult
    {
        private readonly byte[] _result;
        public SimpleBlockResult(byte[] result) => _result = result;
        public byte[] Collect() => _result;
        public int Collect(byte[] destination, int offset)
        {
            Array.Copy(_result, 0, destination, offset, _result.Length);
            return _result.Length;
        }
        public int Collect(Span<byte> destination)
        {
            _result.CopyTo(destination);
            return _result.Length;
        }
        public int GetMaxResultLength() => _result.Length;
    }
}

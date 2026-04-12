#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Builds X.509 certificates using BouncyCastle's X509V3CertificateGenerator with a pluggable
/// ISignatureFactory. This allows signing via remote providers (Vault Transit, Cloud KMS)
/// where the private key never leaves the provider boundary.
/// </summary>
public static class RemoteCertificateBuilder
{
    /// <summary>
    /// Creates a self-signed root CA certificate using remote signing.
    /// </summary>
    public static async Task<X509Certificate2> CreateSelfSignedAsync(
        ISigningProvider provider,
        SigningKeyReference keyRef,
        string subjectDn,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        X509Extension[] extensions,
        HashAlgorithmName hashAlgorithm,
        CancellationToken ct = default)
    {
        var publicKey = await provider.GetPublicKeyAsync(keyRef, ct);
        var bcPublicKey = ConvertToBouncyCastlePublicKey(publicKey);

        var generator = new X509V3CertificateGenerator();
        var subject = new X509Name(subjectDn);

        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetIssuerDN(subject); // self-signed: issuer = subject
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(bcPublicKey);

        // Add extensions
        foreach (var ext in extensions)
        {
            var oid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(ext.Oid!.Value!);
            generator.AddExtension(oid, ext.Critical,
                Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(ext.RawData));
        }

        var sigFactory = new VaultSignatureFactory(provider, keyRef, hashAlgorithm);
        var bcCert = generator.Generate(sigFactory);

        return new X509Certificate2(bcCert.GetEncoded());
    }

    /// <summary>
    /// Creates a CA-signed certificate (intermediate CA or end-entity) using remote signing.
    /// The issuer signs with the provider's key.
    /// </summary>
    public static async Task<X509Certificate2> CreateSignedAsync(
        ISigningProvider provider,
        SigningKeyReference issuerKeyRef,
        X509Certificate2 issuerCert,
        AsymmetricAlgorithm subjectPublicKey,
        string subjectDn,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        X509Extension[] extensions,
        HashAlgorithmName hashAlgorithm,
        CancellationToken ct = default)
    {
        var bcSubjectPublicKey = ConvertToBouncyCastlePublicKey(subjectPublicKey);

        var generator = new X509V3CertificateGenerator();
        var issuerDn = new X509Name(issuerCert.Subject);
        var subject = new X509Name(subjectDn);

        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetIssuerDN(issuerDn);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(bcSubjectPublicKey);

        // Add extensions
        foreach (var ext in extensions)
        {
            var oid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(ext.Oid!.Value!);
            generator.AddExtension(oid, ext.Critical,
                Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(ext.RawData));
        }

        var sigFactory = new VaultSignatureFactory(provider, issuerKeyRef, hashAlgorithm);
        var bcCert = generator.Generate(sigFactory);

        return new X509Certificate2(bcCert.GetEncoded());
    }

    private static AsymmetricKeyParameter ConvertToBouncyCastlePublicKey(AsymmetricAlgorithm key)
    {
        byte[] spki;
        if (key is RSA rsa)
        {
            spki = rsa.ExportSubjectPublicKeyInfo();
        }
        else if (key is ECDsa ecdsa)
        {
            spki = ecdsa.ExportSubjectPublicKeyInfo();
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type: {key.GetType().Name}");
        }

        return Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(spki);
    }

    private static Org.BouncyCastle.Math.BigInteger GenerateSerialNumber()
    {
        var serialBytes = RandomNumberGenerator.GetBytes(16);
        // Ensure positive
        serialBytes[0] &= 0x7F;
        return new Org.BouncyCastle.Math.BigInteger(1, serialBytes);
    }
}

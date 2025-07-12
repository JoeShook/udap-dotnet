#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Model.Registration;
using ECCurve = System.Security.Cryptography.ECCurve;

namespace Udap.Model.Statement;
public class SignedSoftwareStatementBuilder<T> where T : class, ISoftwareStatementSerializer
{
    private readonly List<X509Certificate2> _certificates;
    private readonly T _document;

    private SignedSoftwareStatementBuilder(List<X509Certificate2> certificates, T document)
    {
        _certificates = certificates;
        _document = document;
    }

    public static SignedSoftwareStatementBuilder<T> Create(X509Certificate2 certificate, T document)
    {
        return new SignedSoftwareStatementBuilder<T>([certificate], document);
    }

    public static SignedSoftwareStatementBuilder<T> Create(List<X509Certificate2> certificates, T document)
    {
        return new SignedSoftwareStatementBuilder<T>(certificates, document);
    }

    //
    // No With items...
    // There are plenty of interesting scenarios like loading the x5c hierarchy where
    // we could add more builder methods
    //

    public string Build(string? algorithm = null)
    {
        var x5cStrings = new List<string>();
        var endCertificate = _certificates.First();

        //
        // Short circuit to ECDSA
        //
        if (endCertificate.GetECDsaPublicKey() != null)
        {
            return BuildECDSA(algorithm);
        }

        algorithm ??= UdapConstants.SupportedAlgorithm.RS256;
        
            
        var securityKey = new X509SecurityKey(endCertificate);
        var signingCredentials = new SigningCredentials(securityKey, algorithm);
        x5cStrings.Add(Convert.ToBase64String(endCertificate.Export(X509ContentType.Cert)));


        foreach (var certificate in _certificates.Skip(1))
        {
            x5cStrings.Add(Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
        }

        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", x5cStrings.ToArray() }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = _document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        return signedSoftwareStatement;
    }


    public string BuildECDSA(string? algorithm = null)
    {
        var x5cStrings = new List<string>();
        algorithm ??= UdapConstants.SupportedAlgorithm.ES256;
        var endCertificate = _certificates.First();
        var key = endCertificate.GetECDsaPrivateKey();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            //
            // Windows work around.  Otherwise, works on Linux
            // Short answer: Windows behaves in such a way when importing the pfx
            // it creates the CNG key so it can only be exported encrypted
            // https://github.com/dotnet/runtime/issues/77590#issuecomment-1325896560
            // https://stackoverflow.com/a/57330499/6115838
            //
            var encryptedPrivateKeyBytes = key?.ExportEncryptedPkcs8PrivateKey(
                "ILikePasswords",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            ecdsa.ImportEncryptedPkcs8PrivateKey("ILikePasswords".AsSpan(), encryptedPrivateKeyBytes.AsSpan(), out _);
        }
        else
        {
            ecdsa.ImportECPrivateKey(key?.ExportECPrivateKey(), out _);
        }


        var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), algorithm)
        {
            // If this routine is called multiple times then you must supply the CryptoProvider factory without caching.
            // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1302#issuecomment-606776893
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        x5cStrings.Add(Convert.ToBase64String(endCertificate.Export(X509ContentType.Cert)));

        foreach (var certificate in _certificates.Skip(1))
        {
            x5cStrings.Add(Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
        }

        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", x5cStrings.ToArray() }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = _document.Base64UrlEncode();
        var input = string.Concat(encodedHeader, ".", encodedPayload);
        var encodedSignature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        return signedSoftwareStatement;
    }
}
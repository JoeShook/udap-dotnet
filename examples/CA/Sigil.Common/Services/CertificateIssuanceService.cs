#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.ViewModels;

namespace Sigil.Common.Services;

/// <summary>
/// Certificate generation engine. Creates Root CAs, Intermediate CAs, and end-entity
/// certificates using .NET's CertificateRequest API with extension helpers extracted
/// from Udap.PKI.Generator. Designed for consumption by UI, CLI, and API hosts.
/// </summary>
public class CertificateIssuanceService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;

    public CertificateIssuanceService(IDbContextFactory<SigilDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    /// <summary>
    /// Issues a certificate based on the given request and template.
    /// For Root CAs, IssuingCaCertificateId should be null (self-signed).
    /// For Intermediate CAs and end-entity certs, it must reference a CA with a private key.
    /// </summary>
    public async Task<CertificateIssuanceResult> IssueCertificateAsync(CertificateIssuanceRequest request)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();

        // Load template
        var template = await db.CertificateTemplates.FindAsync(request.TemplateId);
        if (template == null)
            return CertificateIssuanceResult.Failure("Template not found.");

        // Validate community exists
        var community = await db.Communities.FindAsync(request.CommunityId);
        if (community == null)
            return CertificateIssuanceResult.Failure("Community not found.");

        if (string.IsNullOrWhiteSpace(request.SubjectDn))
            return CertificateIssuanceResult.Failure("Subject DN is required.");

        if (string.IsNullOrWhiteSpace(request.PfxPassword))
            return CertificateIssuanceResult.Failure("PFX password is required.");

        // Determine if self-signed (root CA)
        bool isSelfSigned = request.IssuingCaCertificateId == null;

        if (isSelfSigned && template.CertificateType != CertificateType.RootCa)
            return CertificateIssuanceResult.Failure("Only Root CA templates can be used for self-signed certificates.");

        if (!isSelfSigned && template.CertificateType == CertificateType.RootCa)
            return CertificateIssuanceResult.Failure("Root CA template cannot be used with an issuing CA — root CAs are self-signed.");

        // Load issuing CA if not self-signed
        X509Certificate2? issuingCert = null;
        CaCertificate? issuingCaEntity = null;

        if (!isSelfSigned)
        {
            issuingCaEntity = await db.CaCertificates.FindAsync(request.IssuingCaCertificateId);
            if (issuingCaEntity == null)
                return CertificateIssuanceResult.Failure("Issuing CA not found.");

            if (issuingCaEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(issuingCaEntity.PfxPassword))
                return CertificateIssuanceResult.Failure("Issuing CA does not have a private key. Import the PFX first.");

            try
            {
                issuingCert = X509CertificateLoader.LoadPkcs12(
                    issuingCaEntity.EncryptedPfxBytes,
                    issuingCaEntity.PfxPassword,
                    X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                return CertificateIssuanceResult.Failure($"Failed to load issuing CA private key: {ex.Message}");
            }
        }

        try
        {
            // Generate key pair
            using var keyHolder = GenerateKeyPair(template);

            // Build CertificateRequest
            var certRequest = CreateCertificateRequest(template, request.SubjectDn, keyHolder);

            // Add extensions
            AddExtensions(certRequest, template, request, issuingCert);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(template.ValidityDays);

            // Clamp notAfter to issuing CA's expiry — .NET won't issue past the issuer's NotAfter
            if (issuingCert != null && notAfter > issuingCert.NotAfter)
            {
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            }

            // Sign and create certificate
            X509Certificate2 cert;
            if (isSelfSigned)
            {
                cert = certRequest.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                var serialBytes = RandomNumberGenerator.GetBytes(16);
                using var signedCert = certRequest.Create(
                    issuingCert!,
                    notBefore,
                    notAfter,
                    serialBytes);

                // Attach private key
                cert = AttachPrivateKey(signedCert, keyHolder);
            }

            using (cert)
            {
                // Export
                var pfxBytes = cert.Export(X509ContentType.Pkcs12, request.PfxPassword);
                var pem = cert.ExportCertificatePem();

                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                // Determine key size for storage
                int keySize = GetKeySize(cert);

                // Store in database
                bool isCaType = template.CertificateType is CertificateType.RootCa
                    or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        CommunityId = request.CommunityId,
                        ParentId = isSelfSigned ? null : request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = cert.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrl,
                        AuthorityInfoAccessUri = request.AiaUrl,
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        TemplateId = request.TemplateId,
                        Name = certName,
                        Subject = cert.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = template.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert?.Dispose();
        }
    }

    /// <summary>
    /// Re-signs an existing certificate with the same key pair but new serial and validity.
    /// The SKI remains the same so downstream certificate chains continue to validate.
    /// Creates a new certificate entity; the old one is preserved.
    /// </summary>
    public async Task<CertificateIssuanceResult> ResignCertificateAsync(CertificateResignRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.PfxPassword))
            return CertificateIssuanceResult.Failure("PFX password is required.");

        await using var db = await _dbFactory.CreateDbContextAsync();

        // Currently only CA certificates can be re-signed (they have hierarchy)
        if (request.EntityType != "CaCertificate")
            return CertificateIssuanceResult.Failure("Only CA certificates can be re-signed.");

        var caEntity = await db.CaCertificates.FindAsync(request.ExistingCertificateId);
        if (caEntity == null)
            return CertificateIssuanceResult.Failure("Certificate not found.");

        if (caEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(caEntity.PfxPassword))
            return CertificateIssuanceResult.Failure("Certificate does not have a private key.");

        // Load existing cert with private key
        X509Certificate2 existingCert;
        try
        {
            existingCert = X509CertificateLoader.LoadPkcs12(
                caEntity.EncryptedPfxBytes,
                caEntity.PfxPassword,
                X509KeyStorageFlags.Exportable);
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Failed to load certificate: {ex.Message}");
        }

        // Load parent CA for signing (if not self-signed root)
        X509Certificate2? parentCert = null;
        bool isSelfSigned = caEntity.ParentId == null;

        if (!isSelfSigned)
        {
            var parentEntity = await db.CaCertificates.FindAsync(caEntity.ParentId);
            if (parentEntity?.EncryptedPfxBytes == null || string.IsNullOrEmpty(parentEntity.PfxPassword))
            {
                existingCert.Dispose();
                return CertificateIssuanceResult.Failure("Parent CA does not have a private key.");
            }

            try
            {
                parentCert = X509CertificateLoader.LoadPkcs12(
                    parentEntity.EncryptedPfxBytes,
                    parentEntity.PfxPassword,
                    X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                existingCert.Dispose();
                return CertificateIssuanceResult.Failure($"Failed to load parent CA: {ex.Message}");
            }
        }

        try
        {
            // Build CertificateRequest using the SAME key from the existing cert
            var rsaKey = existingCert.GetRSAPrivateKey();
            var ecdsaKey = existingCert.GetECDsaPrivateKey();

            CertificateRequest certRequest;
            if (ecdsaKey != null)
            {
                certRequest = new CertificateRequest(
                    existingCert.SubjectName,
                    ecdsaKey,
                    HashAlgorithmName.SHA256);
            }
            else if (rsaKey != null)
            {
                certRequest = new CertificateRequest(
                    existingCert.SubjectName,
                    rsaKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            else
            {
                return CertificateIssuanceResult.Failure("Unsupported key algorithm.");
            }

            // Copy ALL extensions from the existing certificate
            // This preserves SKI, AKI, BasicConstraints, KeyUsage, SANs, CDP, AIA, etc.
            foreach (var ext in existingCert.Extensions)
            {
                certRequest.CertificateExtensions.Add(ext);
            }

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var originalDuration = existingCert.NotAfter - existingCert.NotBefore;
            var notAfter = request.NotAfter ?? notBefore.Add(originalDuration);

            // Clamp to parent's NotAfter
            if (parentCert != null && notAfter > parentCert.NotAfter)
            {
                notAfter = new DateTimeOffset(parentCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            }

            // Sign with new serial
            X509Certificate2 newCert;
            if (isSelfSigned)
            {
                // Self-signed root: sign with own key
                newCert = certRequest.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                var serialBytes = RandomNumberGenerator.GetBytes(16);
                using var signedCert = certRequest.Create(
                    parentCert!,
                    notBefore,
                    notAfter,
                    serialBytes);

                // Attach the SAME private key
                if (ecdsaKey != null)
                    newCert = signedCert.CopyWithPrivateKey(ecdsaKey);
                else
                    newCert = signedCert.CopyWithPrivateKey(rsaKey!);
            }

            using (newCert)
            {
                var pfxBytes = newCert.Export(X509ContentType.Pkcs12, request.PfxPassword);
                var pem = newCert.ExportCertificatePem();

                // Update the existing entity in-place so all child relationships
                // (issued certs, CRLs, sub-CAs) remain attached to this CA.
                caEntity.X509CertificatePem = pem;
                caEntity.EncryptedPfxBytes = pfxBytes;
                caEntity.PfxPassword = request.PfxPassword;
                caEntity.Thumbprint = newCert.Thumbprint;
                caEntity.SerialNumber = newCert.SerialNumber;
                caEntity.NotBefore = newCert.NotBefore.ToUniversalTime();
                caEntity.NotAfter = newCert.NotAfter.ToUniversalTime();

                await db.SaveChangesAsync();

                return new CertificateIssuanceResult
                {
                    Success = true,
                    EntityId = caEntity.Id,
                    EntityType = "CaCertificate",
                    Thumbprint = newCert.Thumbprint,
                    SerialNumber = newCert.SerialNumber
                };
            }
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Re-sign failed: {ex.Message}");
        }
        finally
        {
            existingCert.Dispose();
            parentCert?.Dispose();
        }
    }

    private static KeyHolder GenerateKeyPair(CertificateTemplate template)
    {
        if (template.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = template.EcdsaCurve?.ToLowerInvariant() switch
            {
                "nistp256" => ECCurve.NamedCurves.nistP256,
                "nistp384" => ECCurve.NamedCurves.nistP384,
                "nistp521" => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP384 // default
            };

            return new KeyHolder(ecdsa: ECDsa.Create(curve));
        }

        return new KeyHolder(rsa: RSA.Create(template.KeySize));
    }

    private static CertificateRequest CreateCertificateRequest(
        CertificateTemplate template,
        string subjectDn,
        KeyHolder keyHolder)
    {
        var hashAlg = template.HashAlgorithm?.ToUpperInvariant() switch
        {
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };

        if (keyHolder.Ecdsa != null)
        {
            return new CertificateRequest(subjectDn, keyHolder.Ecdsa, hashAlg);
        }

        return new CertificateRequest(
            subjectDn,
            keyHolder.Rsa!,
            hashAlg,
            RSASignaturePadding.Pkcs1);
    }

    private static void AddExtensions(
        CertificateRequest certRequest,
        CertificateTemplate template,
        CertificateIssuanceRequest request,
        X509Certificate2? issuingCert)
    {
        // Basic Constraints
        bool hasPathLength = template.IsBasicConstraintsCa && template.PathLengthConstraint.HasValue;
        certRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                template.IsBasicConstraintsCa,
                hasPathLength,
                hasPathLength ? template.PathLengthConstraint!.Value : 0,
                template.IsBasicConstraintsCritical));

        // Key Usage
        var keyUsage = (X509KeyUsageFlags)template.KeyUsageFlags;
        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(keyUsage, template.IsKeyUsageCritical));

        // Subject Key Identifier
        certRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));

        // Authority Key Identifier (if issued by a CA)
        if (issuingCert != null)
        {
            CertificateExtensionHelpers.AddAuthorityKeyIdentifier(issuingCert, certRequest);
        }

        // Extended Key Usage
        if (!string.IsNullOrWhiteSpace(template.ExtendedKeyUsageOids))
        {
            var oids = new OidCollection();
            foreach (var oid in template.ExtendedKeyUsageOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                oids.Add(new Oid(oid));
            }

            if (oids.Count > 0)
            {
                certRequest.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(oids, template.IsExtendedKeyUsageCritical));
            }
        }

        // CRL Distribution Points
        if (template.IncludeCdp && !string.IsNullOrWhiteSpace(request.CdpUrl))
        {
            certRequest.CertificateExtensions.Add(
                CertificateExtensionHelpers.MakeCdp(request.CdpUrl));
        }

        // Authority Information Access
        if (template.IncludeAia && !string.IsNullOrWhiteSpace(request.AiaUrl))
        {
            certRequest.CertificateExtensions.Add(
                CertificateExtensionHelpers.BuildAiaExtension(new Uri(request.AiaUrl)));
        }

        // Subject Alternative Names
        if (request.SubjectAltNames.Count > 0)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var san in request.SubjectAltNames)
            {
                switch (san.Type)
                {
                    case SanType.Uri:
                        sanBuilder.AddUri(new Uri(san.Value));
                        break;
                    case SanType.Dns:
                        sanBuilder.AddDnsName(san.Value);
                        break;
                    case SanType.Email:
                        sanBuilder.AddEmailAddress(san.Value);
                        break;
                    case SanType.IpAddress:
                        sanBuilder.AddIpAddress(IPAddress.Parse(san.Value));
                        break;
                }
            }

            certRequest.CertificateExtensions.Add(sanBuilder.Build());
        }
    }

    private static X509Certificate2 AttachPrivateKey(X509Certificate2 signedCert, KeyHolder keyHolder)
    {
        if (keyHolder.Ecdsa != null)
            return signedCert.CopyWithPrivateKey(keyHolder.Ecdsa);

        return signedCert.CopyWithPrivateKey(keyHolder.Rsa!);
    }

    private static int GetKeySize(X509Certificate2 cert)
    {
        if (cert.GetECDsaPublicKey() is { } ecdsa)
        {
            using (ecdsa)
                return ecdsa.KeySize;
        }

        if (cert.GetRSAPublicKey() is { } rsa)
        {
            using (rsa)
                return rsa.KeySize;
        }

        return 0;
    }

    private static string? ExtractCnFromDn(string dn)
    {
        // Simple CN extraction from "CN=value, O=..."
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed[3..].Trim();
        }

        return null;
    }

    /// <summary>
    /// Holds the generated key pair (either RSA or ECDSA) and disposes it properly.
    /// </summary>
    private sealed class KeyHolder : IDisposable
    {
        public RSA? Rsa { get; }
        public ECDsa? Ecdsa { get; }

        public KeyHolder(RSA? rsa = null, ECDsa? ecdsa = null)
        {
            Rsa = rsa;
            Ecdsa = ecdsa;
        }

        public void Dispose()
        {
            Rsa?.Dispose();
            Ecdsa?.Dispose();
        }
    }
}

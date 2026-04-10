using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Sigil.Common.Services;

public class ChainValidationService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<ChainValidationService> _logger;

    public ChainValidationService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<ChainValidationService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>
    /// Validates a CA certificate's trust chain within its community.
    /// </summary>
    public async Task<ChainValidationResult> ValidateCaCertificateAsync(
        int caCertificateId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var caCert = await db.CaCertificates
            .Include(c => c.Community)
            .FirstOrDefaultAsync(c => c.Id == caCertificateId, ct);

        if (caCert == null)
            return ChainValidationResult.Failed("Certificate not found");

        var allCas = await db.CaCertificates
            .Where(c => c.CommunityId == caCert.CommunityId)
            .ToListAsync(ct);

        var allCrls = await db.Crls
            .Where(c => c.CaCertificate.CommunityId == caCert.CommunityId)
            .Include(c => c.Revocations)
            .ToListAsync(ct);

        return ValidateChain(caCert.X509CertificatePem, caCert.Name, allCas, allCrls);
    }

    /// <summary>
    /// Validates an issued certificate's trust chain within its community.
    /// </summary>
    public async Task<ChainValidationResult> ValidateIssuedCertificateAsync(
        int issuedCertificateId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var issued = await db.IssuedCertificates
            .Include(i => i.IssuingCaCertificate)
                .ThenInclude(ca => ca.Community)
            .FirstOrDefaultAsync(i => i.Id == issuedCertificateId, ct);

        if (issued == null)
            return ChainValidationResult.Failed("Certificate not found");

        var communityId = issued.IssuingCaCertificate.CommunityId;

        var allCas = await db.CaCertificates
            .Where(c => c.CommunityId == communityId)
            .ToListAsync(ct);

        var allCrls = await db.Crls
            .Where(c => c.CaCertificate.CommunityId == communityId)
            .Include(c => c.Revocations)
            .ToListAsync(ct);

        return ValidateChain(issued.X509CertificatePem, issued.Name, allCas, allCrls);
    }

    /// <summary>
    /// Validates a certificate chain from leaf to root using community CA certs and CRLs.
    /// </summary>
    public ChainValidationResult ValidateChain(
        string leafPem,
        string leafName,
        List<CaCertificate> communityCas,
        List<Crl> communityCrls)
    {
        var parser = new X509CertificateParser();
        var chainLinks = new List<ChainLink>();

        // Parse leaf
        BcX509Certificate bcLeaf;
        try
        {
            using var dotNetLeaf = X509Certificate2.CreateFromPem(leafPem);
            bcLeaf = parser.ReadCertificate(dotNetLeaf.RawData);
        }
        catch (Exception ex)
        {
            return ChainValidationResult.Failed($"Cannot parse certificate: {ex.Message}");
        }

        // Parse all community CAs into BouncyCastle certs
        var bcCas = new List<(CaCertificate entity, BcX509Certificate bcCert)>();
        foreach (var ca in communityCas)
        {
            try
            {
                using var dotNetCa = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                var bcCa = parser.ReadCertificate(dotNetCa.RawData);
                bcCas.Add((ca, bcCa));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cannot parse CA certificate {Name}", ca.Name);
            }
        }

        // Build chain iteratively from leaf up to root
        var current = bcLeaf;
        var currentName = leafName;
        var visited = new HashSet<string>();
        bool reachedRoot = false;
        const int maxDepth = 10;

        for (int depth = 0; depth < maxDepth; depth++)
        {
            var thumbprint = Convert.ToHexString(current.GetEncoded().Take(20).ToArray());
            if (!visited.Add(thumbprint))
            {
                chainLinks.Add(ChainLink.Problem(currentName, current, "Circular chain detected"));
                break;
            }

            var link = new ChainLink
            {
                Name = currentName,
                Subject = current.SubjectDN.ToString(),
                Issuer = current.IssuerDN.ToString()
            };

            // Check time validity
            var now = DateTime.UtcNow;
            if (now < current.NotBefore.ToUniversalTime())
            {
                link.Problems.Add("Not yet valid (NotBefore is in the future)");
            }
            if (now > current.NotAfter.ToUniversalTime())
            {
                link.Problems.Add($"Expired (NotAfter: {current.NotAfter:yyyy-MM-dd})");
            }

            // Check basic constraints for non-leaf certs
            if (depth > 0)
            {
                var basicConstraints = current.GetBasicConstraints();
                if (basicConstraints < 0)
                {
                    link.Problems.Add("Not a CA (BasicConstraints CA=false or missing)");
                }
            }

            // Check CRL revocation (skip for self-signed roots)
            if (!current.IssuerDN.Equivalent(current.SubjectDN))
            {
                CheckCrlRevocation(current, link, bcCas, communityCrls);
            }

            // Self-signed? This is a root — verify self-signature
            if (current.IssuerDN.Equivalent(current.SubjectDN))
            {
                try
                {
                    current.Verify(current.GetPublicKey());
                    link.SignatureValid = true;
                }
                catch
                {
                    link.Problems.Add("Self-signature verification failed");
                    link.SignatureValid = false;
                }

                // Check if this root is actually in our community trust store
                var matchedRoot = bcCas.FirstOrDefault(ca =>
                    ca.bcCert.SubjectDN.Equivalent(current.SubjectDN));
                if (matchedRoot.entity != null)
                {
                    link.IsTrustAnchor = true;
                    reachedRoot = true;
                }
                else
                {
                    link.Problems.Add("Root CA not found in community trust store");
                }

                chainLinks.Add(link);
                break;
            }

            // Find issuer in community CAs
            BcX509Certificate? issuerBc = null;
            CaCertificate? issuerEntity = null;

            foreach (var (caEntity, caCert) in bcCas)
            {
                // Match by AKI/SKI first
                if (MatchesKeyIdentifiers(current, caCert))
                {
                    try
                    {
                        current.Verify(caCert.GetPublicKey());
                        issuerBc = caCert;
                        issuerEntity = caEntity;
                        link.SignatureValid = true;
                        break;
                    }
                    catch
                    {
                        // AKI/SKI matched but signature failed — keep looking
                    }
                }
            }

            // Fallback: try DN match + signature verification
            if (issuerBc == null)
            {
                foreach (var (caEntity, caCert) in bcCas)
                {
                    if (caCert.SubjectDN.Equivalent(current.IssuerDN))
                    {
                        try
                        {
                            current.Verify(caCert.GetPublicKey());
                            issuerBc = caCert;
                            issuerEntity = caEntity;
                            link.SignatureValid = true;
                            break;
                        }
                        catch
                        {
                            // DN matched but signature didn't — try next
                        }
                    }
                }
            }

            if (issuerBc == null)
            {
                link.SignatureValid = false;
                link.Problems.Add("Issuer not found in community — chain is incomplete");
                chainLinks.Add(link);
                break;
            }

            chainLinks.Add(link);

            // Move up the chain
            current = issuerBc;
            currentName = issuerEntity?.Name ?? issuerBc.SubjectDN.ToString();
        }

        var isValid = reachedRoot && chainLinks.All(l => l.Problems.Count == 0);

        return new ChainValidationResult
        {
            IsValid = isValid,
            ReachedTrustAnchor = reachedRoot,
            ChainLinks = chainLinks
        };
    }

    private void CheckCrlRevocation(
        BcX509Certificate cert,
        ChainLink link,
        List<(CaCertificate entity, BcX509Certificate bcCert)> bcCas,
        List<Crl> communityCrls)
    {
        // Find which CA issued this cert
        (CaCertificate entity, BcX509Certificate bcCert)? issuerCa = null;
        foreach (var ca in bcCas)
        {
            if (MatchesKeyIdentifiers(cert, ca.bcCert) || ca.bcCert.SubjectDN.Equivalent(cert.IssuerDN))
            {
                try
                {
                    cert.Verify(ca.bcCert.GetPublicKey());
                    issuerCa = ca;
                    break;
                }
                catch { }
            }
        }

        if (issuerCa == null)
        {
            link.CrlStatus = CrlCheckStatus.IssuerNotFound;
            return;
        }

        // Find CRLs for this issuer
        var relevantCrls = communityCrls
            .Where(c => c.CaCertificateId == issuerCa.Value.entity.Id)
            .OrderByDescending(c => c.CrlNumber)
            .ToList();

        if (relevantCrls.Count == 0)
        {
            link.CrlStatus = CrlCheckStatus.NoCrlAvailable;
            link.Problems.Add("No CRL available for revocation checking");
            return;
        }

        // Use the latest CRL
        var latestCrl = relevantCrls[0];

        // Check CRL time validity
        var now = DateTime.UtcNow;
        if (now > latestCrl.NextUpdate)
        {
            link.CrlStatus = CrlCheckStatus.CrlExpired;
            link.Problems.Add($"CRL #{latestCrl.CrlNumber} expired (NextUpdate: {latestCrl.NextUpdate:yyyy-MM-dd})");
            return;
        }

        // Check if this cert is revoked
        var serialHex = cert.SerialNumber.ToString(16).ToUpperInvariant();
        var revocationEntry = latestCrl.Revocations
            .FirstOrDefault(r => r.RevokedCertSerialNumber.Equals(serialHex, StringComparison.OrdinalIgnoreCase));

        if (revocationEntry != null)
        {
            link.CrlStatus = CrlCheckStatus.Revoked;
            var reasonName = revocationEntry.RevocationReason switch
            {
                0 => "Unspecified",
                1 => "Key Compromise",
                2 => "CA Compromise",
                3 => "Affiliation Changed",
                4 => "Superseded",
                5 => "Cessation of Operation",
                6 => "Certificate Hold",
                9 => "Privilege Withdrawn",
                10 => "AA Compromise",
                _ => $"Unknown ({revocationEntry.RevocationReason})"
            };
            link.Problems.Add($"REVOKED on {revocationEntry.RevocationDate:yyyy-MM-dd} — {reasonName}");
        }
        else
        {
            link.CrlStatus = CrlCheckStatus.Good;
        }
    }

    private static bool MatchesKeyIdentifiers(BcX509Certificate subject, BcX509Certificate issuer)
    {
        try
        {
            var akiValue = subject.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
            var skiValue = issuer.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);

            if (akiValue == null || skiValue == null) return false;

            var aki = AuthorityKeyIdentifier.GetInstance(
                Asn1OctetString.GetInstance(akiValue.GetOctets()));
            var ski = SubjectKeyIdentifier.GetInstance(
                Asn1OctetString.GetInstance(skiValue.GetOctets()));

            return aki.GetKeyIdentifier().SequenceEqual(ski.GetKeyIdentifier());
        }
        catch
        {
            return false;
        }
    }
}

public class ChainValidationResult
{
    public bool IsValid { get; init; }
    public bool ReachedTrustAnchor { get; init; }
    public string? Error { get; init; }
    public List<ChainLink> ChainLinks { get; init; } = new();

    public static ChainValidationResult Failed(string error) => new()
    {
        IsValid = false,
        ReachedTrustAnchor = false,
        Error = error
    };
}

public class ChainLink
{
    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public bool? SignatureValid { get; set; }
    public bool IsTrustAnchor { get; set; }
    public CrlCheckStatus CrlStatus { get; set; } = CrlCheckStatus.NotChecked;
    public List<string> Problems { get; set; } = new();

    public bool HasProblems => Problems.Count > 0;

    public static ChainLink Problem(string name, BcX509Certificate cert, string problem) => new()
    {
        Name = name,
        Subject = cert.SubjectDN.ToString(),
        Issuer = cert.IssuerDN.ToString(),
        Problems = { problem }
    };
}

public enum CrlCheckStatus
{
    NotChecked,
    Good,
    Revoked,
    NoCrlAvailable,
    CrlExpired,
    IssuerNotFound
}

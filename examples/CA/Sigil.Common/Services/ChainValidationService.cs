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
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ChainValidationService> _logger;

    public ChainValidationService(
        IDbContextFactory<SigilDbContext> dbFactory,
        IHttpClientFactory httpClientFactory,
        ILogger<ChainValidationService> logger)
    {
        _dbFactory = dbFactory;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    /// Validates all certificates in a community in one pass (parses CAs once).
    /// Uses stored CRLs only (no HTTP) for speed.
    /// Returns a dictionary keyed by thumbprint.
    /// </summary>
    public async Task<Dictionary<string, ChainValidationResult>> ValidateCommunityAsync(
        int communityId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var allCas = await db.CaCertificates
            .Where(c => c.CommunityId == communityId)
            .Include(c => c.IssuedCertificates)
            .ToListAsync(ct);

        var allCrls = await db.Crls
            .Where(c => c.CaCertificate.CommunityId == communityId)
            .Include(c => c.Revocations)
            .ToListAsync(ct);

        // Parse all CA certs once — the expensive part
        var parser = new X509CertificateParser();
        var bcCas = new List<(CaCertificate entity, BcX509Certificate bcCert)>();
        foreach (var ca in allCas)
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

        // Build list of all certs to validate
        var validationTasks = new List<(string Thumbprint, Task<ChainValidationResult> Task)>();

        foreach (var ca in allCas)
        {
            validationTasks.Add((ca.Thumbprint, ValidateChainInternal(
                ca.X509CertificatePem, ca.Name, bcCas, allCrls, skipOnlineCrl: false, ct)));
        }

        foreach (var ca in allCas)
        {
            foreach (var issued in ca.IssuedCertificates)
            {
                validationTasks.Add((issued.Thumbprint, ValidateChainInternal(
                    issued.X509CertificatePem, issued.Name, bcCas, allCrls, skipOnlineCrl: false, ct)));
            }
        }

        // Run all validations in parallel (CRL downloads happen concurrently)
        await Task.WhenAll(validationTasks.Select(t => t.Task));

        var results = new Dictionary<string, ChainValidationResult>();
        foreach (var (thumbprint, task) in validationTasks)
        {
            results[thumbprint] = task.Result;
        }

        return results;
    }

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

        return await ValidateChainAsync(caCert.X509CertificatePem, caCert.Name, allCas, allCrls, ct);
    }

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

        return await ValidateChainAsync(issued.X509CertificatePem, issued.Name, allCas, allCrls, ct);
    }

    public async Task<ChainValidationResult> ValidateChainAsync(
        string leafPem,
        string leafName,
        List<CaCertificate> communityCas,
        List<Crl> communityCrls,
        CancellationToken ct = default)
    {
        return await ValidateChainAsync(leafPem, leafName, communityCas, communityCrls,
            skipOnlineCrl: false, ct);
    }

    public async Task<ChainValidationResult> ValidateChainAsync(
        string leafPem,
        string leafName,
        List<CaCertificate> communityCas,
        List<Crl> communityCrls,
        bool skipOnlineCrl,
        CancellationToken ct = default)
    {
        var parser = new X509CertificateParser();
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

        return await ValidateChainInternal(leafPem, leafName, bcCas, communityCrls, skipOnlineCrl, ct);
    }

    private async Task<ChainValidationResult> ValidateChainInternal(
        string leafPem,
        string leafName,
        List<(CaCertificate entity, BcX509Certificate bcCert)> bcCas,
        List<Crl> communityCrls,
        bool skipOnlineCrl,
        CancellationToken ct)
    {
        var parser = new X509CertificateParser();
        var chainLinks = new List<ChainLink>();

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
                link.Problems.Add("Not yet valid (NotBefore is in the future)");
            if (now > current.NotAfter.ToUniversalTime())
                link.Problems.Add($"Expired (NotAfter: {current.NotAfter:yyyy-MM-dd})");

            // Check basic constraints for non-leaf certs
            if (depth > 0)
            {
                var basicConstraints = current.GetBasicConstraints();
                if (basicConstraints < 0)
                    link.Problems.Add("Not a CA (BasicConstraints CA=false or missing)");
            }

            // Check CRL revocation (skip for self-signed roots)
            if (!current.IssuerDN.Equivalent(current.SubjectDN))
            {
                await CheckCrlRevocationAsync(current, link, bcCas, communityCrls, skipOnlineCrl, ct);
            }

            // Self-signed root
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

            // Find issuer by AKI/SKI
            BcX509Certificate? issuerBc = null;
            CaCertificate? issuerEntity = null;

            foreach (var (caEntity, caCert) in bcCas)
            {
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
                    catch { }
                }
            }

            // Fallback: DN match
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
                        catch { }
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

    private async Task CheckCrlRevocationAsync(
        BcX509Certificate cert,
        ChainLink link,
        List<(CaCertificate entity, BcX509Certificate bcCert)> bcCas,
        List<Crl> communityCrls,
        bool skipOnlineCrl,
        CancellationToken ct)
    {
        // Find issuer
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

        // Try stored CRLs first
        var storedCrls = communityCrls
            .Where(c => c.CaCertificateId == issuerCa.Value.entity.Id)
            .OrderByDescending(c => c.CrlNumber)
            .ToList();

        if (storedCrls.Count > 0)
        {
            var latestCrl = storedCrls[0];
            var now = DateTime.UtcNow;

            if (now <= latestCrl.NextUpdate)
            {
                CheckRevocationInCrl(cert, link, latestCrl, CrlSource.Stored);
                return;
            }

            _logger.LogInformation("Stored CRL #{Number} expired, attempting online resolution", latestCrl.CrlNumber);
        }

        if (skipOnlineCrl)
        {
            if (storedCrls.Count > 0)
            {
                link.CrlStatus = CrlCheckStatus.CrlExpired;
                link.Problems.Add($"CRL #{storedCrls[0].CrlNumber} expired (online check skipped)");
            }
            else
            {
                link.CrlStatus = CrlCheckStatus.NoCrlAvailable;
            }
            return;
        }

        var cdpUrls = ExtractCdpUrls(cert);
        if (cdpUrls.Count == 0)
        {
            if (storedCrls.Count > 0)
            {
                link.CrlStatus = CrlCheckStatus.CrlExpired;
                link.Problems.Add($"CRL #{storedCrls[0].CrlNumber} expired (NextUpdate: {storedCrls[0].NextUpdate:yyyy-MM-dd}), no CDP URL to fetch fresh CRL");
            }
            else
            {
                link.CrlStatus = CrlCheckStatus.NoCrlAvailable;
                link.Problems.Add("No CRL available and no CDP extension for online resolution");
            }
            return;
        }

        foreach (var url in cdpUrls)
        {
            try
            {
                var crlBytes = await DownloadCrlAsync(url, ct);
                if (crlBytes == null) continue;

                var crlParser = new X509CrlParser();
                var downloadedCrl = crlParser.ReadCrl(crlBytes);

                try
                {
                    downloadedCrl.Verify(issuerCa.Value.bcCert.GetPublicKey());
                }
                catch
                {
                    _logger.LogWarning("Downloaded CRL from {Url} failed signature verification", url);
                    continue;
                }

                var now = DateTime.UtcNow;
                if (now < downloadedCrl.ThisUpdate.ToUniversalTime())
                {
                    _logger.LogWarning("Downloaded CRL from {Url} has ThisUpdate in the future", url);
                    continue;
                }

                if (downloadedCrl.NextUpdate.HasValue && now > downloadedCrl.NextUpdate.Value.ToUniversalTime())
                {
                    _logger.LogWarning("Downloaded CRL from {Url} is expired", url);
                }

                long crlNumber = 0;
                var crlNumExt = downloadedCrl.GetExtensionValue(X509Extensions.CrlNumber);
                if (crlNumExt != null)
                {
                    var asn1Num = Org.BouncyCastle.X509.Extension.X509ExtensionUtilities
                        .FromExtensionValue(crlNumExt);
                    crlNumber = DerInteger.GetInstance(asn1Num).LongValueExact;
                }

                var isRevoked = downloadedCrl.IsRevoked(cert);

                if (isRevoked)
                {
                    link.CrlStatus = CrlCheckStatus.Revoked;
                    link.CrlSource = CrlSource.Downloaded;
                    link.CrlSourceUrl = url;

                    var entry = downloadedCrl.GetRevokedCertificate(cert.SerialNumber);
                    var reason = GetRevocationReason(entry);
                    link.Problems.Add($"REVOKED on {entry?.RevocationDate:yyyy-MM-dd} — {reason} (CRL #{crlNumber} from {url})");
                }
                else
                {
                    link.CrlStatus = CrlCheckStatus.Good;
                    link.CrlSource = CrlSource.Downloaded;
                    link.CrlSourceUrl = url;
                }

                _logger.LogInformation("Resolved CRL #{Number} from {Url} for revocation check", crlNumber, url);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to download/parse CRL from {Url}", url);
            }
        }

        if (storedCrls.Count > 0)
        {
            var expiredCrl = storedCrls[0];
            link.CrlStatus = CrlCheckStatus.CrlExpired;
            link.Problems.Add($"CRL #{expiredCrl.CrlNumber} expired, online resolution from CDP failed");
        }
        else
        {
            link.CrlStatus = CrlCheckStatus.CrlFetchFailed;
            link.Problems.Add($"CRL download failed from {string.Join(", ", cdpUrls)}");
        }
    }

    private void CheckRevocationInCrl(BcX509Certificate cert, ChainLink link, Crl storedCrl, CrlSource source)
    {
        var serialHex = cert.SerialNumber.ToString(16).ToUpperInvariant();
        var revocationEntry = storedCrl.Revocations
            .FirstOrDefault(r => r.RevokedCertSerialNumber.Equals(serialHex, StringComparison.OrdinalIgnoreCase));

        if (revocationEntry != null)
        {
            link.CrlStatus = CrlCheckStatus.Revoked;
            link.CrlSource = source;
            var reasonName = GetRevocationReasonName(revocationEntry.RevocationReason);
            link.Problems.Add($"REVOKED on {revocationEntry.RevocationDate:yyyy-MM-dd} — {reasonName}");
        }
        else
        {
            link.CrlStatus = CrlCheckStatus.Good;
            link.CrlSource = source;
        }
    }

    private async Task<byte[]?> DownloadCrlAsync(string url, CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("SigilCrl");

            var separator = url.Contains('?') ? '&' : '?';
            var bustUrl = $"{url}{separator}_t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";

            _logger.LogDebug("Downloading CRL from {Url}", bustUrl);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            var response = await client.GetAsync(bustUrl, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("CRL download returned {StatusCode} from {Url}", response.StatusCode, url);
                return null;
            }

            return await response.Content.ReadAsByteArrayAsync(cts.Token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CRL download failed from {Url}", url);
            return null;
        }
    }

    private static List<string> ExtractCdpUrls(BcX509Certificate cert)
    {
        var urls = new List<string>();
        try
        {
            var cdpExt = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
            if (cdpExt == null) return urls;

            var cdpObj = Asn1OctetString.GetInstance(cdpExt).GetOctets();
            var cdpSeq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(cdpObj));

            foreach (Asn1Encodable dpEncodable in cdpSeq)
            {
                var dp = DistributionPoint.GetInstance(dpEncodable);
                var dpName = dp.DistributionPointName;
                if (dpName?.PointType != DistributionPointName.FullName) continue;

                var generalNames = GeneralNames.GetInstance(dpName.Name);
                foreach (var gn in generalNames.GetNames())
                {
                    if (gn.TagNo == GeneralName.UniformResourceIdentifier)
                    {
                        var uri = gn.Name.ToString();
                        if (uri != null && (uri.StartsWith("http://") || uri.StartsWith("https://")))
                        {
                            urls.Add(uri);
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            // Malformed CDP extension — ignore
        }

        return urls;
    }

    private static string GetRevocationReason(X509CrlEntry? entry)
    {
        if (entry == null) return "Unknown";
        try
        {
            var reasonExt = entry.GetExtensionValue(X509Extensions.ReasonCode);
            if (reasonExt != null)
            {
                var asn1 = Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(reasonExt);
                var code = DerEnumerated.GetInstance(asn1).IntValueExact;
                return GetRevocationReasonName(code);
            }
        }
        catch { }
        return "Unspecified";
    }

    private static string GetRevocationReasonName(int code) => code switch
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
        _ => $"Unknown ({code})"
    };

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
    public CrlSource CrlSource { get; set; } = CrlSource.None;
    public string? CrlSourceUrl { get; set; }
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
    CrlFetchFailed,
    IssuerNotFound
}

public enum CrlSource
{
    None,
    Stored,
    Downloaded
}

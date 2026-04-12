#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.JSInterop;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;
using Sigil.Common.ViewModels;
using Sigil.UI.Services;

namespace Sigil.UI.Components.Pages;

public partial class CertificateExplorer
{
    [Parameter] public int CommunityId { get; set; }

    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private CertificateParsingService ParsingService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private Asn1ParsingService Asn1Parser { get; set; } = null!;
    [Inject] private CrlImportService CrlImporter { get; set; } = null!;
    [Inject] private ChainValidationService ChainValidator { get; set; } = null!;
    [Inject] private CertificateIssuanceService IssuanceService { get; set; } = null!;
    [Inject] private IJSRuntime JS { get; set; } = null!;

    // Tree state
    private List<CommunityOption> communityList = new();
    private CommunityOption? selectedCommunity;
    private string selectedCommunityName = string.Empty;
    private List<CertificateChainNodeViewModel> treeNodes = new();
    private CertificateChainNodeViewModel? selectedNode;
    private X509Certificate2? selectedCert;
    private Asn1Node? asn1Root;
    private CrlViewModel? selectedCrl;
    private ChainValidationResult? chainValidation;
    private bool selectedNodeHasPrivateKey;
    private List<string> subjectAltNames = new();
    private FluentTreeItem? selectedTreeItem;
    private int treeVersion;
    private bool isRevalidating;
    private Dictionary<string, ChainValidationResult> communityValidations = new();

    // Import state
    private bool showDropZone;
    private string? importError;
    private List<string> importErrors = new();
    private bool isImportingBatch;
    private int importProgress;
    private int importTotal;
    private FluentInputFile? fileInput;
    private InputFile? folderInput;
    private Queue<(byte[] Bytes, string FileName)> pendingPasswordQueue = new();

    // Password dialog
    private bool passwordDialogHidden = true;
    private string pfxPassword = string.Empty;
    private string? passwordError;
    private string pendingFileName = string.Empty;
    private byte[]? pendingFileBytes;

    // Move dialog
    private bool moveDialogHidden = true;
    private CommunityOption? moveTargetCommunity;

    // Confirm dialog
    private bool confirmDialogHidden = true;
    private ParsedCertificate? parsedCert;
    private string importName = string.Empty;
    private string? chainMatchDescription;
    private int? matchedParentCaId;

    // CA selection dialog (for unmatched certs)
    private bool caSelectDialogHidden = true;
    private List<CaSelectOption> availableCas = new();
    private CaSelectOption? selectedCaForAssignment;
    private ParsedCertificate? pendingCaSelectParsed;
    private Queue<(byte[] Bytes, string FileName, string? Password)> pendingCaSelectQueue = new();

    // Issuance dialog
    private bool issuanceDialogHidden = true;
    private bool isIssuing;
    private int? issuingCaIdForIssuance;
    private string? issuingCaNameForIssuance;
    private DateTime? issuingCaNotAfter;
    private List<CertificateTemplate> availableTemplates = new();
    private CertificateTemplate? selectedTemplate;
    private string issuanceSubjectDn = string.Empty;
    private string issuanceCertName = string.Empty;
    private DateTime? issuanceNotBeforeNullable = DateTime.UtcNow;
    private DateTime? issuanceNotAfterNullable = DateTime.UtcNow.AddYears(1);
    private string issuanceCdpUrl = string.Empty;
    private string issuanceAiaUrl = string.Empty;
    private List<IssuanceSanEntry> issuanceSans = new();
    private string issuancePfxPassword = string.Empty;

    // Re-sign dialog
    private bool resignDialogHidden = true;
    private bool isResigning;
    private DateTime? resignNotBefore = DateTime.UtcNow;
    private DateTime? resignNotAfter = DateTime.UtcNow.AddYears(5);
    private string resignPfxPassword = string.Empty;

    protected override async Task OnInitializedAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        communityList = await db.Communities
            .OrderBy(c => c.Name)
            .Select(c => new CommunityOption { Id = c.Id, Name = c.Name })
            .ToListAsync();

        if (CommunityId > 0)
        {
            selectedCommunity = communityList.FirstOrDefault(c => c.Id == CommunityId);
            await LoadCommunityTreeAsync(CommunityId);
        }
    }

    private async Task OnCommunitySelected(CommunityOption? option)
    {
        if (option != null)
        {
            selectedCommunity = option;
            CommunityId = option.Id;
            await LoadCommunityTreeAsync(option.Id);
        }
    }

    private async Task LoadCommunityTreeAsync(int communityId)
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        var community = await db.Communities.FindAsync(communityId);
        selectedCommunityName = community?.Name ?? "Unknown";

        // Load ALL CAs for this community in a flat list — EF will fix up
        // the navigation properties (Parent/Children) automatically since
        // all entities are in the same DbContext tracking scope.
        var caCerts = await db.CaCertificates
            .Where(ca => ca.CommunityId == communityId)
            .Include(ca => ca.IssuedCertificates)
            .Include(ca => ca.Crls)
            .OrderBy(ca => ca.Name)
            .ToListAsync();

        // EF relationship fix-up populates ca.Children for all loaded entities,
        // so BuildTreeNode's recursive walk works at any depth.

        // Validate all certs in one pass (parses CAs once, stored CRLs only)
        communityValidations = await ChainValidator.ValidateCommunityAsync(communityId);

        treeNodes = caCerts
            .Where(ca => ca.ParentId == null)
            .Select(rootCa => BuildTreeNode(rootCa, caCerts, communityValidations))
            .ToList();

        treeVersion++;
        selectedTreeItem = null;
        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        chainValidation = null;
        asn1Root = null;
        subjectAltNames.Clear();
    }

    private static CertificateChainNodeViewModel BuildTreeNode(
        CaCertificate ca,
        List<CaCertificate> allCas,
        Dictionary<string, ChainValidationResult> validationResults)
    {
        var caStatus = DeriveStatus(ca.Thumbprint, ca.NotAfter, false, validationResults);

        var node = new CertificateChainNodeViewModel
        {
            Id = ca.Id,
            Name = ca.Name,
            Subject = ca.Subject,
            Thumbprint = ca.Thumbprint,
            NotAfter = ca.NotAfter,
            CertificateRole = ca.ParentId == null ? "RootCA" : "IntermediateCA",
            EntityType = "CaCertificate",
            Status = caStatus
        };

        foreach (var child in ca.Children.OrderBy(c => c.Name))
        {
            node.Children.Add(BuildTreeNode(child, allCas, validationResults));
        }

        foreach (var issued in ca.IssuedCertificates.OrderBy(i => i.Name))
        {
            var issuedStatus = DeriveStatus(issued.Thumbprint, issued.NotAfter, issued.IsRevoked, validationResults);

            node.Children.Add(new CertificateChainNodeViewModel
            {
                Id = issued.Id,
                Name = issued.Name,
                Subject = issued.Subject,
                Thumbprint = issued.Thumbprint,
                NotAfter = issued.NotAfter,
                CertificateRole = "EndEntity",
                EntityType = "IssuedCertificate",
                Status = issuedStatus
            });
        }

        // Add CRL nodes
        foreach (var crl in ca.Crls.OrderByDescending(c => c.CrlNumber))
        {
            var crlStatus = DateTime.UtcNow > crl.NextUpdate
                ? CertificateStatus.Expired
                : DateTime.UtcNow > crl.NextUpdate.AddDays(-7)
                    ? CertificateStatus.Expiring
                    : CertificateStatus.Valid;

            node.Children.Add(new CertificateChainNodeViewModel
            {
                Id = crl.Id,
                Name = $"CRL #{crl.CrlNumber}" + (crl.FileName != null ? $" ({crl.FileName})" : ""),
                Subject = ca.Subject,
                NotAfter = crl.NextUpdate,
                CertificateRole = "CRL",
                EntityType = "Crl",
                Status = crlStatus
            });
        }

        return node;
    }

    private static CertificateStatus DeriveStatus(
        string thumbprint, DateTime notAfter, bool isRevoked,
        Dictionary<string, ChainValidationResult> validationResults)
    {
        if (isRevoked) return CertificateStatus.Revoked;
        if (DateTime.UtcNow > notAfter) return CertificateStatus.Expired;

        // Check chain validation result
        if (validationResults.TryGetValue(thumbprint, out var result))
        {
            if (!result.IsValid)
            {
                // Check if there's a revocation problem in the chain
                var hasRevocation = result.ChainLinks
                    .Any(l => l.CrlStatus == CrlCheckStatus.Revoked);
                if (hasRevocation) return CertificateStatus.Revoked;

                return CertificateStatus.Untrusted;
            }
        }

        if (DateTime.UtcNow > notAfter.AddDays(-30)) return CertificateStatus.Expiring;
        return CertificateStatus.Valid;
    }

    // --- Tree selection ---

    private async Task OnTreeItemSelected(FluentTreeItem? item)
    {
        selectedTreeItem = item;

        if (item?.Data is CertificateChainNodeViewModel node)
        {
            await SelectNode(node);
        }
    }

    private async Task SelectNode(CertificateChainNodeViewModel node)
    {
        selectedNode = node;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        selectedNodeHasPrivateKey = false;
        chainValidation = null;
        asn1Root = null;
        subjectAltNames.Clear();
        CloseIssuerDetails();

        await using var db = await DbFactory.CreateDbContextAsync();

        // CRL selection
        if (node.EntityType == "Crl")
        {
            var crl = await db.Crls
                .Include(c => c.CaCertificate)
                .Include(c => c.Revocations)
                .FirstOrDefaultAsync(c => c.Id == node.Id);

            if (crl != null)
            {
                selectedCrl = new CrlViewModel
                {
                    Id = crl.Id,
                    CaCertificateId = crl.CaCertificateId,
                    CaName = crl.CaCertificate.Name,
                    CrlNumber = crl.CrlNumber,
                    ThisUpdate = crl.ThisUpdate,
                    NextUpdate = crl.NextUpdate,
                    SignatureAlgorithm = crl.SignatureAlgorithm,
                    SignatureValid = crl.SignatureValid,
                    FileName = crl.FileName,
                    RevokedCount = crl.Revocations.Count,
                    ImportedAt = crl.ImportedAt,
                    RevokedCertificates = crl.Revocations
                        .OrderBy(r => r.RevocationDate)
                        .Select(r => new RevokedCertEntry
                        {
                            SerialNumber = r.RevokedCertSerialNumber,
                            Thumbprint = r.RevokedCertThumbprint,
                            RevocationDate = r.RevocationDate,
                            ReasonCode = r.RevocationReason
                        })
                        .ToList()
                };

                // Parse CRL ASN.1 structure
                asn1Root = Asn1Parser.Parse(crl.RawBytes);
            }

            return;
        }

        string? pem = null;
        string? sans = null;

        if (node.EntityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync(node.Id);
            pem = ca?.X509CertificatePem;
            selectedNodeHasPrivateKey = ca?.EncryptedPfxBytes != null;
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync(node.Id);
            pem = issued?.X509CertificatePem;
            sans = issued?.SubjectAltNames;
            selectedNodeHasPrivateKey = issued?.EncryptedPfxBytes != null;
        }

        if (!string.IsNullOrEmpty(pem))
        {
            try
            {
                selectedCert = X509Certificate2.CreateFromPem(pem);
                asn1Root = Asn1Parser.ParsePem(pem);

                // Use pre-computed result from tree load
                if (!string.IsNullOrEmpty(node.Thumbprint)
                    && communityValidations.TryGetValue(node.Thumbprint, out var cached))
                {
                    chainValidation = cached;
                }
                else
                {
                    // Fallback: validate on demand
                    if (node.EntityType == "CaCertificate")
                        chainValidation = await ChainValidator.ValidateCaCertificateAsync(node.Id);
                    else
                        chainValidation = await ChainValidator.ValidateIssuedCertificateAsync(node.Id);
                }
            }
            catch { }
        }

        if (!string.IsNullOrEmpty(sans))
        {
            subjectAltNames = sans.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }
        else if (selectedCert != null)
        {
            var sanExt = selectedCert.Extensions["2.5.29.17"];
            if (sanExt != null)
            {
                try
                {
                    subjectAltNames = sanExt.Format(multiLine: true)
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                }
                catch { }
            }
        }

        await UpdateTreeHighlightsAsync();
    }

    private async Task RevalidateSelectedAsync()
    {
        if (selectedNode == null || selectedNode.EntityType == "Crl") return;

        isRevalidating = true;
        StateHasChanged();

        try
        {
            // Full validation with online CRL resolution
            if (selectedNode.EntityType == "CaCertificate")
                chainValidation = await ChainValidator.ValidateCaCertificateAsync(selectedNode.Id);
            else
                chainValidation = await ChainValidator.ValidateIssuedCertificateAsync(selectedNode.Id);

            // Update the stored results and tree node status
            if (!string.IsNullOrEmpty(selectedNode.Thumbprint) && chainValidation != null)
            {
                communityValidations[selectedNode.Thumbprint] = chainValidation;
                selectedNode.Status = DeriveStatus(
                    selectedNode.Thumbprint, selectedNode.NotAfter, false, communityValidations);
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Validation failed: {ex.Message}");
        }
        finally
        {
            isRevalidating = false;
            StateHasChanged();
        }
    }

    private string GetCerDownloadUrl()
    {
        if (selectedNode == null) return "#";
        return selectedNode.EntityType == "CaCertificate"
            ? $"/api/ca/{selectedNode.Id}/download/cer"
            : $"/api/issued/{selectedNode.Id}/download/cer";
    }

    private string GetPfxDownloadUrl()
    {
        if (selectedNode == null) return "#";
        return selectedNode.EntityType == "CaCertificate"
            ? $"/api/ca/{selectedNode.Id}/download/p12"
            : $"/api/issued/{selectedNode.Id}/download/p12";
    }

    private async Task<int?> FindCaBySkiAsync(SigilDbContext db, string authorityKeyIdentifier)
    {
        var cas = await db.CaCertificates
            .Where(ca => ca.CommunityId == CommunityId)
            .ToListAsync();

        foreach (var ca in cas)
        {
            try
            {
                using var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                var skiExt = caCert.Extensions["2.5.29.14"];
                if (skiExt != null)
                {
                    var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
                    if (ski.SubjectKeyIdentifier == authorityKeyIdentifier)
                    {
                        return ca.Id;
                    }
                }
            }
            catch { }
        }

        return null;
    }

    /// <summary>
    /// Finds the issuing CA by matching the cert's Issuer DN against CA Subject DNs,
    /// then verifying the signature. Used as fallback when AKI/SKI match fails.
    /// </summary>
    private async Task<int?> FindCaByDnAndSignatureAsync(SigilDbContext db, X509Certificate2 cert)
    {
        var cas = await db.CaCertificates
            .Where(ca => ca.CommunityId == CommunityId)
            .ToListAsync();

        var bcParser = new Org.BouncyCastle.X509.X509CertificateParser();
        var bcCert = bcParser.ReadCertificate(cert.RawData);

        foreach (var ca in cas)
        {
            try
            {
                using var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                var bcCa = bcParser.ReadCertificate(caCert.RawData);

                if (bcCa.SubjectDN.Equivalent(bcCert.IssuerDN))
                {
                    bcCert.Verify(bcCa.GetPublicKey());
                    return ca.Id; // Signature verified — this is the issuer
                }
            }
            catch { }
        }

        return null;
    }

    private static string NodeColor(CertificateStatus status) => status switch
    {
        CertificateStatus.Expired => "#e94560",
        CertificateStatus.Revoked => "#9c27b0",
        CertificateStatus.Untrusted => "#d32f2f",
        CertificateStatus.Expiring => "#ff9800",
        _ => ""
    };

    private static bool IsError(CertificateStatus status) =>
        status is CertificateStatus.Expired or CertificateStatus.Revoked or CertificateStatus.Untrusted;

    private string GetPublicKeyInfo()
    {
        if (selectedCert == null) return "Unknown";
        var rsa = selectedCert.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        var ecdsa = selectedCert.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return "Unknown";
    }

    // --- Drag & drop import ---

    private async Task OnFilesCompleted(IEnumerable<FluentInputFileEventArgs> files)
    {
        importError = null;
        importErrors.Clear();

        var fileList = files.Where(f => f.LocalFile != null && !string.IsNullOrEmpty(f.Name)).ToList();

        if (fileList.Count == 0) return;

        // Single file — use the interactive confirm dialog flow
        if (fileList.Count == 1)
        {
            var args = fileList[0];
            try
            {
                var fileBytes = await File.ReadAllBytesAsync(args.LocalFile!.FullName);
                await ProcessUploadedFile(fileBytes, args.Name);
            }
            catch (Exception ex)
            {
                importError = $"Failed to read '{args.Name}': {ex.Message}";
            }
            return;
        }

        // Multiple files — batch import without individual confirm dialogs
        await BatchImportFiles(fileList.Select(f => (f.LocalFile!.FullName, f.Name)).ToList());
    }

    private async Task OnFolderSelected(InputFileChangeEventArgs e)
    {
        importError = null;
        importErrors.Clear();

        var validExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".pfx", ".p12", ".cer", ".crt", ".pem", ".der", ".crl" };

        var filesToProcess = new List<(string TempPath, string FileName)>();

        foreach (var file in e.GetMultipleFiles(500))
        {
            var ext = Path.GetExtension(file.Name).ToLowerInvariant();
            if (!validExtensions.Contains(ext)) continue;

            // Save browser file to temp
            var tempPath = Path.GetTempFileName();
            try
            {
                await using var stream = file.OpenReadStream(10 * 1024 * 1024);
                await using var fs = File.Create(tempPath);
                await stream.CopyToAsync(fs);
                filesToProcess.Add((tempPath, file.Name));
            }
            catch (Exception ex)
            {
                importErrors.Add($"Failed to read '{file.Name}': {ex.Message}");
            }
        }

        if (filesToProcess.Count > 0)
        {
            await BatchImportFiles(filesToProcess);

            // Cleanup temp files
            foreach (var (tempPath, _) in filesToProcess)
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    private async Task BatchImportFiles(List<(string FilePath, string FileName)> files)
    {
        isImportingBatch = true;
        importTotal = files.Count;
        importProgress = 0;
        int successCount = 0;

        // Read all files and detect roles so we can sort CAs before end-entity certs
        var fileEntries = new List<(byte[] Bytes, string FileName, int SortOrder)>();
        foreach (var (filePath, fileName) in files)
        {
            try
            {
                var fileBytes = await File.ReadAllBytesAsync(filePath);
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                int sortOrder;
                if (ext == ".crl")
                {
                    sortOrder = 3; // CRLs last
                }
                else
                {
                    // Quick-parse to detect role for sorting
                    var parsed = ext is ".pfx" or ".p12"
                        ? (ParsingService.Parse(fileBytes, fileName, "") ?? ParsingService.Parse(fileBytes, fileName, "udap-test"))
                        : ParsingService.Parse(fileBytes, fileName);

                    if (parsed?.DetectedRole == DetectedCertRole.RootCa)
                        sortOrder = 0; // Roots first
                    else if (parsed?.DetectedRole == DetectedCertRole.IntermediateCa)
                        sortOrder = 1; // Then intermediates
                    else
                        sortOrder = 2; // End-entity certs after CAs
                    parsed?.Certificate.Dispose();
                }

                fileEntries.Add((fileBytes, fileName, sortOrder));
            }
            catch (Exception ex)
            {
                importErrors.Add($"Failed to read '{fileName}': {ex.Message}");
            }
        }

        var sorted = fileEntries.OrderBy(f => f.SortOrder).ToList();
        importTotal = sorted.Count;

        // First pass
        var retryList = new List<(byte[] Bytes, string FileName)>();
        foreach (var (fileBytes, fileName, _) in sorted)
        {
            importProgress++;
            StateHasChanged();

            try
            {
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                if (ext == ".crl")
                {
                    var result = await CrlImporter.ImportCrlAsync(fileBytes, fileName, CommunityId);
                    if (result.IsSuccess)
                        successCount++;
                    else
                        importErrors.Add($"{fileName}: {result.Error}");
                }
                else
                {
                    var errorCountBefore = importErrors.Count;
                    var imported = await TryAutoImportCert(fileBytes, fileName);
                    if (imported)
                        successCount++;
                    else if (importErrors.Count > errorCountBefore)
                        retryList.Add((fileBytes, fileName)); // Had an error (not just queued for password)
                }
            }
            catch (Exception ex)
            {
                importErrors.Add($"{fileName}: {ex.Message}");
            }
        }

        // Second pass: retry files that failed (CAs should now exist)
        if (retryList.Count > 0)
        {
            // Clear errors from first pass for files we're retrying
            var retryNames = retryList.Select(r => r.FileName).ToHashSet();
            importErrors.RemoveAll(e => retryNames.Any(n => e.StartsWith($"{n}:")));

            foreach (var (fileBytes, fileName) in retryList)
            {
                try
                {
                    var imported = await TryAutoImportCert(fileBytes, fileName);
                    if (imported)
                        successCount++;
                }
                catch (Exception ex)
                {
                    importErrors.Add($"{fileName}: {ex.Message}");
                }
            }
        }

        isImportingBatch = false;

        if (successCount > 0)
        {
            ToastService.ShowCopyableSuccess($"Imported {successCount} of {files.Count} files.");
            await LoadCommunityTreeAsync(CommunityId);
        }

        if (importErrors.Count > 0 && successCount == 0
            && pendingPasswordQueue.Count == 0 && pendingCaSelectQueue.Count == 0)
        {
            importError = "No files were imported successfully.";
        }

        // Process queued PFX files that need manual password entry, then unmatched certs
        if (pendingPasswordQueue.Count > 0)
            ProcessNextPendingPassword();
        else if (pendingCaSelectQueue.Count > 0)
            ProcessNextPendingCaSelect();
    }

    /// <summary>
    /// Auto-imports a certificate without the confirm dialog.
    /// Tries empty password, then "udap-test" for PFX files.
    /// </summary>
    private async Task<bool> TryAutoImportCert(byte[] fileBytes, string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        ParsedCertificate? parsed = null;
        string? usedPassword = null;

        if (ext is ".pfx" or ".p12")
        {
            parsed = ParsingService.Parse(fileBytes, fileName, "");
            if (parsed != null) usedPassword = "";

            if (parsed == null)
            {
                parsed = ParsingService.Parse(fileBytes, fileName, "udap-test");
                if (parsed != null) usedPassword = "udap-test";
            }

            if (parsed == null)
            {
                // Queue for manual password entry after batch completes
                pendingPasswordQueue.Enqueue((fileBytes, fileName));
                return false;
            }
        }
        else
        {
            parsed = ParsingService.Parse(fileBytes, fileName);
            if (parsed == null)
            {
                importErrors.Add($"{fileName}: Could not parse certificate");
                return false;
            }
        }

        try
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            var cert = parsed.Certificate;
            var thumbprint = cert.Thumbprint;

            // Check for existing cert with same thumbprint — merge if found
            var existingCa = await db.CaCertificates
                .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint && c.CommunityId == CommunityId);

            if (existingCa != null)
            {
                // Merge: upgrade public-only to operational if PFX now available
                if (parsed.HasPrivateKey && existingCa.EncryptedPfxBytes == null)
                {
                    existingCa.EncryptedPfxBytes = fileBytes;
                    existingCa.PfxPassword = usedPassword;
                    await db.SaveChangesAsync();
                    parsed.Certificate.Dispose();
                    return true;
                }

                // Already have this cert (same thumbprint, already has key or both public)
                parsed.Certificate.Dispose();
                return true; // Not an error, just a no-op
            }

            var existingIssued = await db.IssuedCertificates
                .Include(i => i.IssuingCaCertificate)
                .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint
                    && c.IssuingCaCertificate.CommunityId == CommunityId);

            if (existingIssued != null)
            {
                if (parsed.HasPrivateKey && existingIssued.EncryptedPfxBytes == null)
                {
                    existingIssued.EncryptedPfxBytes = fileBytes;
                    existingIssued.PfxPassword = usedPassword;
                    await db.SaveChangesAsync();
                    parsed.Certificate.Dispose();
                    return true;
                }

                parsed.Certificate.Dispose();
                return true;
            }

            // New cert — find where it belongs in the chain
            if (parsed.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
            {
                int? parentId = null;
                if (parsed.DetectedRole == DetectedCertRole.IntermediateCa)
                {
                    if (parsed.AuthorityKeyIdentifier != null)
                        parentId = await FindCaBySkiAsync(db, parsed.AuthorityKeyIdentifier);

                    // Fallback: match by Issuer DN + signature verification
                    parentId ??= await FindCaByDnAndSignatureAsync(db, cert);
                }

                db.CaCertificates.Add(new CaCertificate
                {
                    CommunityId = CommunityId,
                    ParentId = parentId,
                    Name = Path.GetFileNameWithoutExtension(fileName),
                    Subject = cert.Subject,
                    X509CertificatePem = cert.ExportCertificatePem(),
                    EncryptedPfxBytes = parsed.HasPrivateKey ? fileBytes : null,
                    PfxPassword = parsed.HasPrivateKey ? usedPassword : null,
                    Thumbprint = thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = parsed.Algorithm,
                    KeySize = parsed.KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    CertSecurityLevel = CertSecurityLevel.Software,
                    Enabled = true
                });
            }
            else
            {
                int? issuingCaId = null;
                if (parsed.AuthorityKeyIdentifier != null)
                {
                    issuingCaId = await FindCaBySkiAsync(db, parsed.AuthorityKeyIdentifier);
                }

                // Fallback: match by Issuer DN + signature verification
                issuingCaId ??= await FindCaByDnAndSignatureAsync(db, cert);

                if (issuingCaId == null)
                {
                    // Queue for manual CA selection
                    pendingCaSelectQueue.Enqueue((fileBytes, fileName, usedPassword));
                    parsed.Certificate.Dispose();
                    return false;
                }

                db.IssuedCertificates.Add(new IssuedCertificate
                {
                    IssuingCaCertificateId = issuingCaId.Value,
                    Name = Path.GetFileNameWithoutExtension(fileName),
                    Subject = cert.Subject,
                    SubjectAltNames = parsed.SubjectAltNames,
                    X509CertificatePem = cert.ExportCertificatePem(),
                    EncryptedPfxBytes = parsed.HasPrivateKey ? fileBytes : null,
                    PfxPassword = parsed.HasPrivateKey ? usedPassword : null,
                    Thumbprint = thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = parsed.Algorithm,
                    KeySize = parsed.KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    Enabled = true
                });
            }

            await db.SaveChangesAsync();
            parsed.Certificate.Dispose();
            return true;
        }
        catch (Exception ex)
        {
            importErrors.Add($"{fileName}: {ex.Message}");
            parsed.Certificate.Dispose();
            return false;
        }
    }

    private async Task TriggerFolderUpload()
    {
        await JS.InvokeVoidAsync("sigilFolderUpload", "folder-input");
    }

    // --- Delete & Move ---

    private async Task DeleteSelectedAsync()
    {
        if (selectedNode == null) return;

        var dialog = await DialogService.ShowConfirmationAsync(
            $"Delete '{selectedNode.Name}'? This cannot be undone.",
            "Delete", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (result.Cancelled) return;

        await using var db = await DbFactory.CreateDbContextAsync();

        switch (selectedNode.EntityType)
        {
            case "CaCertificate":
                var ca = await db.CaCertificates.FindAsync(selectedNode.Id);
                if (ca != null) { db.CaCertificates.Remove(ca); }
                break;
            case "IssuedCertificate":
                var issued = await db.IssuedCertificates.FindAsync(selectedNode.Id);
                if (issued != null) { db.IssuedCertificates.Remove(issued); }
                break;
            case "Crl":
                var crl = await db.Crls.FindAsync(selectedNode.Id);
                if (crl != null) { db.Crls.Remove(crl); }
                break;
        }

        await db.SaveChangesAsync();
        ToastService.ShowCopyableSuccess($"Deleted '{selectedNode.Name}'");

        // Clear all selection state including the FluentTreeItem reference
        // to prevent the tree view from holding a stale DOM reference
        selectedTreeItem = null;
        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        chainValidation = null;
        asn1Root = null;
        CloseIssuerDetails();

        await LoadCommunityTreeAsync(CommunityId);
    }

    private void ShowMoveDialog()
    {
        moveTargetCommunity = null;
        moveDialogHidden = false;
    }

    private async Task MoveSelectedAsync()
    {
        if (selectedNode == null || moveTargetCommunity == null) return;

        await using var db = await DbFactory.CreateDbContextAsync();
        var targetId = moveTargetCommunity.Id;

        switch (selectedNode.EntityType)
        {
            case "CaCertificate":
                var ca = await db.CaCertificates.FindAsync(selectedNode.Id);
                if (ca != null)
                {
                    ca.CommunityId = targetId;
                    ca.ParentId = null; // Detach from current parent — will need re-linking in target
                }
                break;
            case "IssuedCertificate":
                var issued = await db.IssuedCertificates
                    .Include(i => i.IssuingCaCertificate)
                    .FirstOrDefaultAsync(i => i.Id == selectedNode.Id);
                if (issued != null)
                {
                    // Find a matching CA in the target community by AKI/SKI
                    int? newIssuingCaId = null;
                    try
                    {
                        using var issuedCert = X509Certificate2.CreateFromPem(issued.X509CertificatePem);
                        var akiExt = issuedCert.Extensions["2.5.29.35"];
                        if (akiExt?.RawData != null && akiExt.RawData.Length >= 6)
                        {
                            var data = akiExt.RawData;
                            if (data[2] == 0x80)
                            {
                                var len = data[3];
                                var keyId = new byte[len];
                                Array.Copy(data, 4, keyId, 0, len);
                                var aki = Convert.ToHexString(keyId);

                                var targetCas = await db.CaCertificates
                                    .Where(c => c.CommunityId == targetId)
                                    .ToListAsync();

                                foreach (var targetCa in targetCas)
                                {
                                    using var tCert = X509Certificate2.CreateFromPem(targetCa.X509CertificatePem);
                                    var skiExt = tCert.Extensions["2.5.29.14"];
                                    if (skiExt != null)
                                    {
                                        var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
                                        if (ski.SubjectKeyIdentifier == aki)
                                        {
                                            newIssuingCaId = targetCa.Id;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }

                    if (newIssuingCaId == null)
                    {
                        // Fallback: first CA in target
                        var fallbackCa = await db.CaCertificates
                            .Where(c => c.CommunityId == targetId)
                            .OrderByDescending(c => c.ParentId)
                            .FirstOrDefaultAsync();
                        newIssuingCaId = fallbackCa?.Id;
                    }

                    if (newIssuingCaId == null)
                    {
                        ToastService.ShowCopyableError("Target community has no CA certificates");
                        moveDialogHidden = true;
                        return;
                    }

                    issued.IssuingCaCertificateId = newIssuingCaId.Value;
                }
                break;
        }

        await db.SaveChangesAsync();
        moveDialogHidden = true;

        ToastService.ShowCopyableSuccess($"Moved '{selectedNode.Name}' to '{moveTargetCommunity.Name}'");

        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        chainValidation = null;

        await LoadCommunityTreeAsync(CommunityId);
    }

    private async Task ProcessUploadedFile(byte[] fileBytes, string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        if (ext == ".crl")
        {
            await ImportCrlAsync(fileBytes, fileName);
            return;
        }

        if (ext is ".pfx" or ".p12")
        {
            // Try with empty password first
            var parsed = ParsingService.Parse(fileBytes, fileName, "");
            if (parsed == null)
            {
                // Try common default
                parsed = ParsingService.Parse(fileBytes, fileName, "udap-test");
            }

            if (parsed != null)
            {
                await ShowConfirmDialogAsync(parsed);
            }
            else
            {
                // Need password
                pendingFileBytes = fileBytes;
                pendingFileName = fileName;
                pfxPassword = string.Empty;
                passwordError = null;
                passwordDialogHidden = false;
            }
        }
        else
        {
            var parsed = ParsingService.Parse(fileBytes, fileName);
            if (parsed != null)
            {
                await ShowConfirmDialogAsync(parsed);
            }
            else
            {
                importError = $"Could not parse certificate from '{fileName}'. Ensure it is a valid certificate file.";
            }
        }
    }

    private void ProcessNextPendingPassword()
    {
        if (pendingPasswordQueue.Count == 0)
        {
            // Password queue done — process any unmatched certs
            if (pendingCaSelectQueue.Count > 0)
                ProcessNextPendingCaSelect();
            return;
        }

        var (bytes, name) = pendingPasswordQueue.Dequeue();
        pendingFileBytes = bytes;
        pendingFileName = name;
        pfxPassword = string.Empty;
        passwordError = null;
        passwordDialogHidden = false;
    }

    private async Task ImportWithPasswordAsync()
    {
        if (pendingFileBytes == null) return;

        passwordError = null;
        var parsed = ParsingService.Parse(pendingFileBytes, pendingFileName, pfxPassword);
        if (parsed != null)
        {
            passwordDialogHidden = true;
            passwordError = null;
            pendingFileBytes = null;

            // In batch mode (queue has items or came from batch), auto-import
            if (pendingPasswordQueue.Count > 0)
            {
                await TryAutoImportCertWithParsed(parsed, pendingFileName, pfxPassword);
                await LoadCommunityTreeAsync(CommunityId);
                ProcessNextPendingPassword();
            }
            else
            {
                await ShowConfirmDialogAsync(parsed);
            }
        }
        else
        {
            // Keep dialog open — let user retry with a different password
            passwordError = "Incorrect password. Try again.";
            pfxPassword = string.Empty;
        }
    }

    private async Task SkipPasswordFile()
    {
        passwordDialogHidden = true;
        passwordError = null;
        importErrors.Add($"{pendingFileName}: Skipped (no password provided)");
        pendingFileBytes = null;
        ProcessNextPendingPassword();
    }

    private void CancelPasswordDialog()
    {
        passwordDialogHidden = true;
        passwordError = null;
        pendingFileBytes = null;
        pendingPasswordQueue.Clear();
    }

    /// <summary>
    /// Auto-imports a parsed cert (used after successful password entry in batch mode).
    /// </summary>
    private async Task TryAutoImportCertWithParsed(ParsedCertificate parsed, string fileName, string password)
    {
        try
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            var cert = parsed.Certificate;
            var thumbprint = cert.Thumbprint;

            // Check for existing
            var existingCa = await db.CaCertificates
                .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint && c.CommunityId == CommunityId);
            if (existingCa != null)
            {
                if (parsed.HasPrivateKey && existingCa.EncryptedPfxBytes == null)
                {
                    existingCa.EncryptedPfxBytes = parsed.RawFileBytes;
                    existingCa.PfxPassword = password;
                    await db.SaveChangesAsync();
                }
                parsed.Certificate.Dispose();
                ToastService.ShowCopyableSuccess($"Imported '{fileName}'");
                return;
            }

            var existingIssued = await db.IssuedCertificates
                .Include(i => i.IssuingCaCertificate)
                .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint
                    && c.IssuingCaCertificate.CommunityId == CommunityId);
            if (existingIssued != null)
            {
                if (parsed.HasPrivateKey && existingIssued.EncryptedPfxBytes == null)
                {
                    existingIssued.EncryptedPfxBytes = parsed.RawFileBytes;
                    existingIssued.PfxPassword = password;
                    await db.SaveChangesAsync();
                }
                parsed.Certificate.Dispose();
                ToastService.ShowCopyableSuccess($"Imported '{fileName}'");
                return;
            }

            if (parsed.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
            {
                int? parentId = null;
                if (parsed.DetectedRole == DetectedCertRole.IntermediateCa)
                {
                    if (parsed.AuthorityKeyIdentifier != null)
                        parentId = await FindCaBySkiAsync(db, parsed.AuthorityKeyIdentifier);

                    parentId ??= await FindCaByDnAndSignatureAsync(db, cert);
                }

                db.CaCertificates.Add(new CaCertificate
                {
                    CommunityId = CommunityId,
                    ParentId = parentId,
                    Name = Path.GetFileNameWithoutExtension(fileName),
                    Subject = cert.Subject,
                    X509CertificatePem = cert.ExportCertificatePem(),
                    EncryptedPfxBytes = parsed.HasPrivateKey ? parsed.RawFileBytes : null,
                    PfxPassword = parsed.HasPrivateKey ? password : null,
                    Thumbprint = thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = parsed.Algorithm,
                    KeySize = parsed.KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    CertSecurityLevel = CertSecurityLevel.Software,
                    Enabled = true
                });
            }
            else
            {
                int? issuingCaId = parsed.AuthorityKeyIdentifier != null
                    ? await FindCaBySkiAsync(db, parsed.AuthorityKeyIdentifier)
                    : null;

                // Fallback: match by Issuer DN + signature verification
                issuingCaId ??= await FindCaByDnAndSignatureAsync(db, cert);

                if (issuingCaId == null)
                {
                    // Queue for manual CA selection
                    pendingCaSelectQueue.Enqueue((parsed.RawFileBytes ?? Array.Empty<byte>(), fileName, password));
                    parsed.Certificate.Dispose();
                    return;
                }

                db.IssuedCertificates.Add(new IssuedCertificate
                {
                    IssuingCaCertificateId = issuingCaId.Value,
                    Name = Path.GetFileNameWithoutExtension(fileName),
                    Subject = cert.Subject,
                    SubjectAltNames = parsed.SubjectAltNames,
                    X509CertificatePem = cert.ExportCertificatePem(),
                    EncryptedPfxBytes = parsed.HasPrivateKey ? parsed.RawFileBytes : null,
                    PfxPassword = parsed.HasPrivateKey ? password : null,
                    Thumbprint = thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = parsed.Algorithm,
                    KeySize = parsed.KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    Enabled = true
                });
            }

            await db.SaveChangesAsync();
            parsed.Certificate.Dispose();
            ToastService.ShowCopyableSuccess($"Imported '{fileName}'");
        }
        catch (Exception ex)
        {
            importErrors.Add($"{fileName}: {ex.Message}");
            parsed.Certificate.Dispose();
        }
    }

    private async Task ShowConfirmDialogAsync(ParsedCertificate parsed)
    {
        parsedCert = parsed;
        importName = Path.GetFileNameWithoutExtension(parsed.FileName);
        matchedParentCaId = null;
        chainMatchDescription = null;

        // Try to find where this cert fits in the existing chain
        if (parsed.DetectedRole != DetectedCertRole.RootCa && parsed.AuthorityKeyIdentifier != null)
        {
            await using var db = await DbFactory.CreateDbContextAsync();

            var matchingCa = await db.CaCertificates
                .Where(ca => ca.CommunityId == CommunityId)
                .ToListAsync();

            foreach (var ca in matchingCa)
            {
                // Load the CA cert to get its SKI
                try
                {
                    var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                    var skiExt = caCert.Extensions["2.5.29.14"];
                    if (skiExt != null)
                    {
                        var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
                        if (ski.SubjectKeyIdentifier == parsed.AuthorityKeyIdentifier)
                        {
                            matchedParentCaId = ca.Id;
                            chainMatchDescription = $"Issued by: {ca.Name} ({ca.Subject})";
                            break;
                        }
                    }
                    caCert.Dispose();
                }
                catch { }
            }

            if (matchedParentCaId == null)
            {
                chainMatchDescription = "No matching issuer found in this community. Will be added as a root.";
            }
        }

        confirmDialogHidden = false;
        StateHasChanged();
    }

    private async Task ConfirmImportAsync()
    {
        if (parsedCert == null || string.IsNullOrWhiteSpace(importName)) return;

        try
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            var cert = parsedCert.Certificate;

            if (parsedCert.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
            {
                var entity = new CaCertificate
                {
                    CommunityId = CommunityId,
                    ParentId = parsedCert.DetectedRole == DetectedCertRole.IntermediateCa ? matchedParentCaId : null,
                    Name = importName.Trim(),
                    Subject = cert.Subject,
                    X509CertificatePem = cert.ExportCertificatePem(),
                    EncryptedPfxBytes = parsedCert.HasPrivateKey ? parsedCert.RawFileBytes : null,
                    PfxPassword = parsedCert.HasPrivateKey ? pfxPassword : null,
                    Thumbprint = cert.Thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = parsedCert.Algorithm,
                    KeySize = parsedCert.KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    CertSecurityLevel = CertSecurityLevel.Software,
                    Enabled = true
                };

                db.CaCertificates.Add(entity);
            }
            else
            {
                var issuingCaId = matchedParentCaId;

                // Fallback: match by Issuer DN + signature verification
                issuingCaId ??= await FindCaByDnAndSignatureAsync(db, cert);

                if (issuingCaId == null)
                {
                    // Pass the already-parsed cert to the CA selection dialog (no re-parse needed)
                    confirmDialogHidden = true;
                    pendingCaSelectParsed = parsedCert;
                    parsedCert = null; // Transfer ownership, don't dispose
                    await ShowCaSelectDialog(
                        pendingCaSelectParsed.RawFileBytes,
                        pendingCaSelectParsed.FileName,
                        pendingCaSelectParsed.HasPrivateKey ? pfxPassword : null);
                    return;
                }

                var entity = new IssuedCertificate
                {
                    IssuingCaCertificateId = issuingCaId.Value,
                    Name = importName.Trim(),
                    Subject = cert.Subject,
                    SubjectAltNames = parsedCert.SubjectAltNames,
                    X509CertificatePem = cert.ExportCertificatePem(),
                    EncryptedPfxBytes = parsedCert.HasPrivateKey ? parsedCert.RawFileBytes : null,
                    PfxPassword = parsedCert.HasPrivateKey ? pfxPassword : null,
                    Thumbprint = cert.Thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = parsedCert.Algorithm,
                    KeySize = parsedCert.KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    Enabled = true
                };

                db.IssuedCertificates.Add(entity);
            }

            await db.SaveChangesAsync();

            confirmDialogHidden = true;
            showDropZone = false;
            importError = null;
            parsedCert?.Certificate.Dispose();
            parsedCert = null;

            ToastService.ShowCopyableSuccess($"Certificate '{importName}' imported successfully.");
            await LoadCommunityTreeAsync(CommunityId);
        }
        catch (Exception ex)
        {
            importError = $"Import failed: {ex.Message}";
            confirmDialogHidden = true;
        }
    }

    private async Task ImportCrlAsync(byte[] crlBytes, string fileName)
    {
        var result = await CrlImporter.ImportCrlAsync(crlBytes, fileName, CommunityId);

        if (!result.IsSuccess)
        {
            importError = result.Error;
            return;
        }

        showDropZone = false;
        var sigStatus = result.SignatureValid ? "signature valid" : "signature INVALID";
        var nextUpdateStr = result.NextUpdate?.ToString("yyyy-MM-dd") ?? "unknown";
        ToastService.ShowCopyableSuccess(
            $"CRL #{result.CrlNumber} imported ({sigStatus}): {result.RevokedCount} revocation(s), next update {nextUpdateStr}");
    }

    private void CancelConfirmDialog()
    {
        confirmDialogHidden = true;
        parsedCert?.Certificate.Dispose();
        parsedCert = null;
    }

    private static string GetRoleBadgeColor(DetectedCertRole role) => role switch
    {
        DetectedCertRole.RootCa => "#2d6a4f",
        DetectedCertRole.IntermediateCa => "#1976d2",
        DetectedCertRole.EndEntity => "#666",
        _ => "#666"
    };

    // --- CA selection for unmatched certs ---

    private async Task LoadAvailableCasAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();
        availableCas = await db.CaCertificates
            .Where(ca => ca.CommunityId == CommunityId)
            .OrderBy(ca => ca.ParentId == null ? 0 : 1) // Roots first
            .ThenBy(ca => ca.Name)
            .Select(ca => new CaSelectOption
            {
                Id = ca.Id,
                Name = ca.Name,
                Subject = ca.Subject,
                IsRoot = ca.ParentId == null
            })
            .ToListAsync();
    }

    private async Task ShowCaSelectDialog(byte[] fileBytes, string fileName, string? password)
    {
        await LoadAvailableCasAsync();

        if (availableCas.Count == 0)
        {
            importErrors.Add($"{fileName}: No CAs exist in this community to assign under");
            return;
        }

        pendingFileBytes = fileBytes;
        pendingFileName = fileName;
        pfxPassword = password ?? string.Empty;
        selectedCaForAssignment = null;
        caSelectDialogHidden = false;
        StateHasChanged();
    }

    private async void ProcessNextPendingCaSelect()
    {
        if (pendingCaSelectQueue.Count == 0) return;

        var (bytes, name, password) = pendingCaSelectQueue.Dequeue();
        pendingCaSelectParsed = null; // Batch items need re-parse
        await ShowCaSelectDialog(bytes, name, password);
    }

    private async Task ConfirmCaAssignmentAsync()
    {
        if (selectedCaForAssignment == null) return;

        // Use pre-parsed cert if available, otherwise re-parse from bytes
        var parsed = pendingCaSelectParsed;
        if (parsed == null && pendingFileBytes != null)
        {
            var ext = Path.GetExtension(pendingFileName).ToLowerInvariant();
            parsed = ext is ".pfx" or ".p12"
                ? ParsingService.Parse(pendingFileBytes, pendingFileName, pfxPassword)
                : ParsingService.Parse(pendingFileBytes, pendingFileName);
        }

        if (parsed == null)
        {
            ToastService.ShowCopyableError($"Could not parse '{pendingFileName}'");
            caSelectDialogHidden = true;
            pendingCaSelectParsed = null;
            ProcessNextPendingCaSelect();
            return;
        }

        try
        {
            await SaveWithCaAssignmentAsync(parsed);
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Import failed: {ex.Message}");
            parsed.Certificate.Dispose();
        }
        pendingCaSelectParsed = null;

        caSelectDialogHidden = true;
        pendingFileBytes = null;

        if (pendingCaSelectQueue.Count > 0)
        {
            ProcessNextPendingCaSelect();
        }
        else
        {
            await LoadCommunityTreeAsync(CommunityId);
        }
    }

    private async Task SaveWithCaAssignmentAsync(ParsedCertificate parsed)
    {
        await using var db = await DbFactory.CreateDbContextAsync();
        var cert = parsed.Certificate;
        var thumbprint = cert.Thumbprint;

        // Check for existing cert — merge if duplicate (e.g. .cer + .pfx for same cert)
        var existingCa = await db.CaCertificates
            .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint && c.CommunityId == CommunityId);
        if (existingCa != null)
        {
            if (parsed.HasPrivateKey && existingCa.EncryptedPfxBytes == null)
            {
                existingCa.EncryptedPfxBytes = pendingFileBytes;
                existingCa.PfxPassword = pfxPassword;
                await db.SaveChangesAsync();
            }
            parsed.Certificate.Dispose();
            ToastService.ShowCopyableSuccess($"Merged PFX into existing '{existingCa.Name}'");
            return;
        }

        var existingIssued = await db.IssuedCertificates
            .Include(i => i.IssuingCaCertificate)
            .FirstOrDefaultAsync(c => c.Thumbprint == thumbprint
                && c.IssuingCaCertificate.CommunityId == CommunityId);
        if (existingIssued != null)
        {
            if (parsed.HasPrivateKey && existingIssued.EncryptedPfxBytes == null)
            {
                existingIssued.EncryptedPfxBytes = pendingFileBytes;
                existingIssued.PfxPassword = pfxPassword;
                await db.SaveChangesAsync();
            }
            parsed.Certificate.Dispose();
            ToastService.ShowCopyableSuccess($"Merged PFX into existing '{existingIssued.Name}'");
            return;
        }

        // New cert — assign under selected CA
        if (parsed.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
        {
            db.CaCertificates.Add(new CaCertificate
            {
                CommunityId = CommunityId,
                ParentId = selectedCaForAssignment!.Id,
                Name = Path.GetFileNameWithoutExtension(pendingFileName),
                Subject = cert.Subject,
                X509CertificatePem = cert.ExportCertificatePem(),
                EncryptedPfxBytes = parsed.HasPrivateKey ? pendingFileBytes : null,
                PfxPassword = parsed.HasPrivateKey ? pfxPassword : null,
                Thumbprint = thumbprint,
                SerialNumber = cert.SerialNumber,
                KeyAlgorithm = parsed.Algorithm,
                KeySize = parsed.KeySize,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                CertSecurityLevel = CertSecurityLevel.Software,
                Enabled = true
            });
        }
        else
        {
            db.IssuedCertificates.Add(new IssuedCertificate
            {
                IssuingCaCertificateId = selectedCaForAssignment!.Id,
                Name = Path.GetFileNameWithoutExtension(pendingFileName),
                Subject = cert.Subject,
                SubjectAltNames = parsed.SubjectAltNames,
                X509CertificatePem = cert.ExportCertificatePem(),
                EncryptedPfxBytes = parsed.HasPrivateKey ? pendingFileBytes : null,
                PfxPassword = parsed.HasPrivateKey ? pfxPassword : null,
                Thumbprint = thumbprint,
                SerialNumber = cert.SerialNumber,
                KeyAlgorithm = parsed.Algorithm,
                KeySize = parsed.KeySize,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                Enabled = true
            });
        }

        await db.SaveChangesAsync();
        parsed.Certificate.Dispose();
        ToastService.ShowCopyableSuccess($"'{Path.GetFileNameWithoutExtension(pendingFileName)}' assigned under '{selectedCaForAssignment!.Name}'");
    }

    private void SkipCaAssignment()
    {
        caSelectDialogHidden = true;
        importErrors.Add($"{pendingFileName}: Skipped (no CA selected)");
        pendingFileBytes = null;
        ProcessNextPendingCaSelect();
    }

    private void CancelCaAssignment()
    {
        caSelectDialogHidden = true;
        pendingFileBytes = null;
        pendingCaSelectQueue.Clear();
    }

    // Issuer detail state
    private X509Certificate2? issuerCert;
    private CertificateChainNodeViewModel? issuerNode;
    private Asn1Node? issuerAsn1Root;

    // Issuance constants
    private static readonly SanType[] sanTypeOptions = Enum.GetValues<SanType>();

    private static string GetSanPlaceholder(SanType type) => type switch
    {
        SanType.Uri => "https://example.com/fhir/r4",
        SanType.Dns => "example.com",
        SanType.Email => "admin@example.com",
        SanType.IpAddress => "192.168.1.1",
        _ => ""
    };

    // --- Issuer Navigation Methods ---

    private async Task UpdateTreeHighlightsAsync()
    {
        try
        {
            var selectedId = selectedNode != null ? $"tree-{selectedNode.Thumbprint}" : null;
            var issuerId = issuerNode != null ? $"tree-{issuerNode.Thumbprint}" : null;
            await JS.InvokeVoidAsync("sigilHighlightTree", selectedId, issuerId);
        }
        catch { /* JS not ready yet */ }
    }

    private string GetTreeItemCrlStyle(CertificateChainNodeViewModel node)
    {
        if (IsError(node.Status))
            return $"color: {NodeColor(node.Status)};";
        return "font-style: italic; opacity: 0.8;";
    }

    private async Task LoadIssuerDetailsAsync()
    {
        if (selectedCert == null) return;
        await LoadIssuerByCert(selectedCert);
    }

    private async Task LoadIssuerOfIssuerDetailsAsync()
    {
        if (issuerCert == null || issuerCert.Subject == issuerCert.Issuer) return;

        // The current issuer becomes the selected cert, and we load its issuer
        var prevIssuer = issuerCert;

        // Find the node for the current issuer and make it the primary selection
        var issuerThumbprint = issuerCert.Thumbprint;
        var node = FindNodeByThumbprint(treeNodes, issuerThumbprint);
        if (node != null)
        {
            await SelectNode(node);
        }

        // Now load the issuer of that cert
        await LoadIssuerByCert(selectedCert!);
    }

    private async Task LoadIssuerByCert(X509Certificate2 cert)
    {
        CloseIssuerDetails();

        if (cert.Subject == cert.Issuer) return; // self-signed, no parent

        // Find issuer by AKI → SKI match, or by DN match
        await using var db = await DbFactory.CreateDbContextAsync();

        var akiValue = GetAkiKeyId(cert);
        CaCertificate? issuerEntity = null;

        if (akiValue != null)
        {
            // Find CA whose SKI matches our AKI
            var cas = await db.CaCertificates
                .Where(ca => ca.CommunityId == CommunityId)
                .ToListAsync();

            foreach (var ca in cas)
            {
                try
                {
                    using var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                    var ski = caCert.Extensions["2.5.29.14"];
                    if (ski != null)
                    {
                        var skiHex = Convert.ToHexString(ski.RawData.AsSpan(2));
                        if (string.Equals(skiHex, akiValue, StringComparison.OrdinalIgnoreCase))
                        {
                            issuerEntity = ca;
                            break;
                        }
                    }
                }
                catch { }
            }
        }

        if (issuerEntity == null)
        {
            // Fallback: match by issuer DN
            var cas = await db.CaCertificates
                .Where(ca => ca.CommunityId == CommunityId && ca.Subject == cert.Issuer)
                .ToListAsync();

            issuerEntity = cas.FirstOrDefault();
        }

        if (issuerEntity == null) return;

        try
        {
            issuerCert = X509Certificate2.CreateFromPem(issuerEntity.X509CertificatePem);
            issuerAsn1Root = Asn1Parser.ParsePem(issuerEntity.X509CertificatePem);
            issuerNode = FindNodeByThumbprint(treeNodes, issuerEntity.Thumbprint);
        }
        catch { }

        StateHasChanged();
        await UpdateTreeHighlightsAsync();
    }

    private void CloseIssuerDetails()
    {
        issuerCert?.Dispose();
        issuerCert = null;
        issuerNode = null;
        issuerAsn1Root = null;
    }

    private async Task CloseIssuerDetailsAsync()
    {
        CloseIssuerDetails();
        await UpdateTreeHighlightsAsync();
    }

    private static string? GetAkiKeyId(X509Certificate2 cert)
    {
        var akiExt = cert.Extensions["2.5.29.35"];
        if (akiExt == null || akiExt.RawData.Length < 6) return null;

        // AKI is a SEQUENCE containing [0] KeyIdentifier (tag 0x80)
        // Simple parse: skip SEQUENCE header, look for tag 0x80
        var data = akiExt.RawData;
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == 0x80)
            {
                int len = data[i + 1];
                if (i + 2 + len <= data.Length)
                {
                    return Convert.ToHexString(data.AsSpan(i + 2, len));
                }
            }
        }

        return null;
    }

    private static CertificateChainNodeViewModel? FindNodeByThumbprint(
        List<CertificateChainNodeViewModel> nodes, string thumbprint)
    {
        foreach (var node in nodes)
        {
            if (string.Equals(node.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                return node;

            var found = FindNodeByThumbprint(node.Children, thumbprint);
            if (found != null) return found;
        }

        return null;
    }

    private string GetIssuerPublicKeyInfo()
    {
        if (issuerCert == null) return "";
        using var rsa = issuerCert.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        using var ecdsa = issuerCert.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return "Unknown";
    }

    // --- Issuance Methods ---

    private async Task ShowIssuanceDialog(int? issuingCaId, string? issuingCaName)
    {
        issuingCaIdForIssuance = issuingCaId;
        issuingCaNameForIssuance = issuingCaName;
        issuingCaNotAfter = null;

        await using var db = await DbFactory.CreateDbContextAsync();

        // Load issuing CA's NotAfter to clamp validity
        if (issuingCaId.HasValue)
        {
            var ca = await db.CaCertificates.FindAsync(issuingCaId.Value);
            issuingCaNotAfter = ca?.NotAfter;
        }

        var allTemplates = await db.CertificateTemplates
            .OrderBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync();

        if (issuingCaId == null)
        {
            // Self-signed root only
            availableTemplates = allTemplates
                .Where(t => t.CertificateType == CertificateType.RootCa)
                .ToList();
        }
        else
        {
            // Intermediate + end-entity templates
            availableTemplates = allTemplates
                .Where(t => t.CertificateType != CertificateType.RootCa)
                .ToList();
        }

        selectedTemplate = availableTemplates.FirstOrDefault();
        OnTemplateSelected(selectedTemplate);

        issuanceSans.Clear();
        issuancePfxPassword = string.Empty;
        issuanceCertName = string.Empty;
        issuanceSubjectDn = string.Empty;
        isIssuing = false;

        issuanceDialogHidden = false;
    }

    private void OnTemplateSelected(CertificateTemplate? template)
    {
        selectedTemplate = template;
        if (template == null) return;

        issuanceNotBeforeNullable = DateTime.UtcNow;
        var desiredNotAfter = DateTime.UtcNow.AddDays(template.ValidityDays);
        // Clamp to issuing CA's expiry
        if (issuingCaNotAfter.HasValue && desiredNotAfter > issuingCaNotAfter.Value)
            desiredNotAfter = issuingCaNotAfter.Value;
        issuanceNotAfterNullable = desiredNotAfter;

        issuanceSubjectDn = template.SubjectTemplate ?? string.Empty;
        issuanceCdpUrl = template.CdpUrlTemplate ?? string.Empty;
        issuanceAiaUrl = template.AiaUrlTemplate ?? string.Empty;

        // Pre-populate SAN entries from template's SubjectAltNameTypes
        issuanceSans.Clear();
        if (!string.IsNullOrWhiteSpace(template.SubjectAltNameTypes))
        {
            foreach (var sanType in template.SubjectAltNameTypes.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var type = sanType.Trim().ToUpperInvariant() switch
                {
                    "URI" => SanType.Uri,
                    "DNS" => SanType.Dns,
                    "EMAIL" => SanType.Email,
                    "IP" => SanType.IpAddress,
                    _ => SanType.Uri
                };
                issuanceSans.Add(new IssuanceSanEntry { Type = type, Value = string.Empty });
            }
        }
    }

    private void AddSanEntry()
    {
        issuanceSans.Add(new IssuanceSanEntry { Type = SanType.Uri, Value = string.Empty });
    }

    private void RemoveSanEntry(IssuanceSanEntry entry)
    {
        issuanceSans.Remove(entry);
    }

    private async Task IssueCertificateAsync()
    {
        if (selectedTemplate == null || string.IsNullOrWhiteSpace(issuanceSubjectDn)) return;

        isIssuing = true;
        StateHasChanged();

        try
        {
            var request = new CertificateIssuanceRequest
            {
                IssuingCaCertificateId = issuingCaIdForIssuance,
                TemplateId = selectedTemplate.Id,
                CommunityId = CommunityId,
                SubjectDn = issuanceSubjectDn,
                CertificateName = issuanceCertName,
                SubjectAltNames = issuanceSans
                    .Where(s => !string.IsNullOrWhiteSpace(s.Value))
                    .Select(s => new SanEntry(s.Type, s.Value))
                    .ToList(),
                CdpUrl = selectedTemplate.IncludeCdp && !string.IsNullOrWhiteSpace(issuanceCdpUrl) ? issuanceCdpUrl : null,
                AiaUrl = selectedTemplate.IncludeAia && !string.IsNullOrWhiteSpace(issuanceAiaUrl) ? issuanceAiaUrl : null,
                NotBefore = issuanceNotBeforeNullable.HasValue ? new DateTimeOffset(issuanceNotBeforeNullable.Value, TimeSpan.Zero) : null,
                NotAfter = issuanceNotAfterNullable.HasValue ? new DateTimeOffset(issuanceNotAfterNullable.Value, TimeSpan.Zero) : null,
                PfxPassword = issuancePfxPassword,
            };

            var result = await IssuanceService.IssueCertificateAsync(request);

            if (result.Success)
            {
                issuanceDialogHidden = true;
                ToastService.ShowCopyableSuccess($"Certificate issued: {result.Thumbprint}");
                await LoadCommunityTreeAsync(CommunityId);
            }
            else
            {
                ToastService.ShowCopyableError(result.Error ?? "Unknown error");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Issuance failed: {ex.Message}");
        }
        finally
        {
            isIssuing = false;
            StateHasChanged();
        }
    }

    private async Task ShowRenewDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        // Determine the issuing CA
        int? issuingCaId = null;
        string? issuingCaName = null;

        await using var db = await DbFactory.CreateDbContextAsync();

        if (selectedNode.CertificateRole == "EndEntity")
        {
            var issued = await db.IssuedCertificates
                .Include(i => i.IssuingCaCertificate)
                .FirstOrDefaultAsync(i => i.Thumbprint == selectedNode.Thumbprint);
            if (issued != null)
            {
                issuingCaId = issued.IssuingCaCertificateId;
                issuingCaName = issued.IssuingCaCertificate.Name;
            }
        }
        else if (selectedNode.CertificateRole == "IntermediateCA")
        {
            var ca = await db.CaCertificates
                .Include(c => c.Parent)
                .FirstOrDefaultAsync(c => c.Thumbprint == selectedNode.Thumbprint);
            if (ca?.Parent != null)
            {
                issuingCaId = ca.ParentId;
                issuingCaName = ca.Parent.Name;
            }
        }
        else if (selectedNode.CertificateRole == "RootCA")
        {
            // Root CA renewal = new self-signed root
            issuingCaId = null;
            issuingCaName = null;
        }

        await ShowIssuanceDialog(issuingCaId, issuingCaName);

        // Pre-select a template matching the original cert's role
        var targetType = selectedNode.CertificateRole switch
        {
            "RootCA" => CertificateType.RootCa,
            "IntermediateCA" => CertificateType.IntermediateCa,
            "EndEntity" => CertificateType.EndEntityClient, // default to client for end-entity
            _ => CertificateType.EndEntityClient
        };

        // Try to match the original cert's template if it had one
        if (selectedNode.CertificateRole == "EndEntity")
        {
            var issued = await db.IssuedCertificates.FindAsync(selectedNode.Id);
            if (issued?.TemplateId != null)
            {
                var match = availableTemplates.FirstOrDefault(t => t.Id == issued.TemplateId);
                if (match != null)
                {
                    selectedTemplate = match;
                    OnTemplateSelected(match);
                }
            }
        }

        // Fallback: match by cert type
        if (selectedTemplate == null || selectedTemplate.CertificateType != targetType)
        {
            var match = availableTemplates.FirstOrDefault(t => t.CertificateType == targetType)
                        ?? availableTemplates.FirstOrDefault();
            if (match != null)
            {
                selectedTemplate = match;
                OnTemplateSelected(match);
            }
        }

        // Pre-fill from existing cert
        issuanceSubjectDn = selectedCert.Subject;
        issuanceCertName = selectedNode.Name + " (renewed)";

        // Extract SANs from existing cert
        // Format varies: "URL=https://..." or "DNS Name=example.com" or "URI:https://..."
        // or from DB storage: "Uri:https://..." / semicolon-delimited
        issuanceSans.Clear();
        foreach (var san in subjectAltNames)
        {
            var trimmed = san.Trim();
            if (TryParseSan(trimmed, "URL=", SanType.Uri, out var entry) ||
                TryParseSan(trimmed, "URI:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "Uri:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "DNS Name=", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "DNS:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "Dns:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "RFC822 Name=", SanType.Email, out entry) ||
                TryParseSan(trimmed, "email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "Email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "IP Address=", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IP:", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IpAddress:", SanType.IpAddress, out entry))
            {
                issuanceSans.Add(entry);
            }
        }
    }

    // --- Re-sign Methods ---

    private async Task ShowResignDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        // Load parent CA's NotAfter for clamping
        await using var db = await DbFactory.CreateDbContextAsync();
        DateTime? parentNotAfter = null;
        var caEntity = await db.CaCertificates.FindAsync(selectedNode.Id);
        if (caEntity?.ParentId != null)
        {
            var parent = await db.CaCertificates.FindAsync(caEntity.ParentId);
            parentNotAfter = parent?.NotAfter;
        }

        resignNotBefore = DateTime.UtcNow;
        // Default to the same duration as the original cert
        var originalDuration = selectedCert.NotAfter - selectedCert.NotBefore;
        var desiredNotAfter = DateTime.UtcNow.Add(originalDuration);

        // Clamp to parent's NotAfter if applicable
        if (parentNotAfter.HasValue && desiredNotAfter > parentNotAfter.Value)
            desiredNotAfter = parentNotAfter.Value;

        resignNotAfter = desiredNotAfter;
        resignPfxPassword = string.Empty;
        isResigning = false;
        resignDialogHidden = false;
    }

    private async Task ResignCertificateAsync()
    {
        if (selectedNode == null) return;

        isResigning = true;
        StateHasChanged();

        try
        {
            var request = new CertificateResignRequest
            {
                ExistingCertificateId = selectedNode.Id,
                EntityType = selectedNode.EntityType,
                NotBefore = resignNotBefore.HasValue ? new DateTimeOffset(resignNotBefore.Value, TimeSpan.Zero) : null,
                NotAfter = resignNotAfter.HasValue ? new DateTimeOffset(resignNotAfter.Value, TimeSpan.Zero) : null,
                PfxPassword = resignPfxPassword,
            };

            var result = await IssuanceService.ResignCertificateAsync(request);

            if (result.Success)
            {
                resignDialogHidden = true;
                ToastService.ShowCopyableSuccess($"Certificate re-signed (same key): {result.Thumbprint}");
                await LoadCommunityTreeAsync(CommunityId);
            }
            else
            {
                ToastService.ShowCopyableError(result.Error ?? "Unknown error");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Re-sign failed: {ex.Message}");
        }
        finally
        {
            isResigning = false;
            StateHasChanged();
        }
    }

    private static bool TryParseSan(string value, string prefix, SanType type, out IssuanceSanEntry entry)
    {
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            entry = new IssuanceSanEntry { Type = type, Value = value[prefix.Length..].Trim() };
            return true;
        }
        entry = null!;
        return false;
    }

    private static string GetCertTypeLabel(CertificateType ct) => ct switch
    {
        CertificateType.RootCa => "Root CA",
        CertificateType.IntermediateCa => "Intermediate CA",
        CertificateType.EndEntityClient => "Client",
        CertificateType.EndEntityServer => "Server",
        _ => ct.ToString()
    };

    public class CommunityOption
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    public class CaSelectOption
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public bool IsRoot { get; set; }
        public string DisplayName => IsRoot ? $"[Root] {Name}" : $"[Intermediate] {Name}";
    }

    public class IssuanceSanEntry
    {
        public SanType Type { get; set; } = SanType.Uri;
        public string Value { get; set; } = string.Empty;
    }
}

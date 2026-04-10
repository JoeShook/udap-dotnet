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
    [Inject] private IJSRuntime JS { get; set; } = null!;

    // Tree state
    private List<CommunityOption> communityList = new();
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

    protected override async Task OnInitializedAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        communityList = await db.Communities
            .OrderBy(c => c.Name)
            .Select(c => new CommunityOption { Id = c.Id, Name = c.Name })
            .ToListAsync();

        if (CommunityId > 0)
        {
            await LoadCommunityTreeAsync(CommunityId);
        }
    }

    private async Task OnCommunitySelected(CommunityOption? option)
    {
        if (option != null)
        {
            CommunityId = option.Id;
            await LoadCommunityTreeAsync(option.Id);
        }
    }

    private async Task LoadCommunityTreeAsync(int communityId)
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        var community = await db.Communities.FindAsync(communityId);
        selectedCommunityName = community?.Name ?? "Unknown";

        var caCerts = await db.CaCertificates
            .Where(ca => ca.CommunityId == communityId)
            .Include(ca => ca.Children)
            .Include(ca => ca.IssuedCertificates)
            .Include(ca => ca.Crls)
            .OrderBy(ca => ca.Name)
            .ToListAsync();

        // Validate all certs in one pass (parses CAs once, stored CRLs only)
        communityValidations = await ChainValidator.ValidateCommunityAsync(communityId);

        treeNodes = caCerts
            .Where(ca => ca.ParentId == null)
            .Select(rootCa => BuildTreeNode(rootCa, caCerts, communityValidations))
            .ToList();

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

            // Update the stored results
            if (!string.IsNullOrEmpty(selectedNode.Thumbprint) && chainValidation != null)
                communityValidations[selectedNode.Thumbprint] = chainValidation;
        }
        catch (Exception ex)
        {
            ToastService.ShowError($"Validation failed: {ex.Message}");
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
            ? $"/api/ca/{selectedNode.Id}/download/pfx"
            : $"/api/issued/{selectedNode.Id}/download/pfx";
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

        // Sort: process CAs first (root > intermediate > end-entity), CRLs last
        // This ensures the chain exists before we try to match end certs and CRLs
        var sorted = files
            .OrderBy(f =>
            {
                var ext = Path.GetExtension(f.FileName).ToLowerInvariant();
                if (ext == ".crl") return 3; // CRLs last
                // PFX/CER — try to detect role from file, but we'll just import in order
                return 1;
            })
            .ToList();

        foreach (var (filePath, fileName) in sorted)
        {
            importProgress++;
            StateHasChanged();

            try
            {
                var fileBytes = await File.ReadAllBytesAsync(filePath);
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
                    var imported = await TryAutoImportCert(fileBytes, fileName);
                    if (imported)
                        successCount++;
                }
            }
            catch (Exception ex)
            {
                importErrors.Add($"{fileName}: {ex.Message}");
            }
        }

        isImportingBatch = false;

        if (successCount > 0)
        {
            ToastService.ShowSuccess($"Imported {successCount} of {files.Count} files.");
            await LoadCommunityTreeAsync(CommunityId);
        }

        if (importErrors.Count > 0 && successCount == 0 && pendingPasswordQueue.Count == 0)
        {
            importError = "No files were imported successfully.";
        }

        // Process queued PFX files that need manual password entry
        ProcessNextPendingPassword();
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
                if (parsed.DetectedRole == DetectedCertRole.IntermediateCa && parsed.AuthorityKeyIdentifier != null)
                {
                    parentId = await FindCaBySkiAsync(db, parsed.AuthorityKeyIdentifier);
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

                if (issuingCaId == null)
                {
                    var firstCa = await db.CaCertificates
                        .Where(ca => ca.CommunityId == CommunityId)
                        .OrderByDescending(ca => ca.ParentId)
                        .FirstOrDefaultAsync();
                    issuingCaId = firstCa?.Id;
                }

                if (issuingCaId == null)
                {
                    importErrors.Add($"{fileName}: No CA found to issue under");
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
        ToastService.ShowSuccess($"Deleted '{selectedNode.Name}'");

        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        chainValidation = null;

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
                        ToastService.ShowError("Target community has no CA certificates");
                        moveDialogHidden = true;
                        return;
                    }

                    issued.IssuingCaCertificateId = newIssuingCaId.Value;
                }
                break;
        }

        await db.SaveChangesAsync();
        moveDialogHidden = true;

        ToastService.ShowSuccess($"Moved '{selectedNode.Name}' to '{moveTargetCommunity.Name}'");

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
        if (pendingPasswordQueue.Count == 0) return;

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
                ToastService.ShowSuccess($"Imported '{fileName}'");
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
                ToastService.ShowSuccess($"Imported '{fileName}'");
                return;
            }

            if (parsed.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
            {
                int? parentId = null;
                if (parsed.DetectedRole == DetectedCertRole.IntermediateCa && parsed.AuthorityKeyIdentifier != null)
                    parentId = await FindCaBySkiAsync(db, parsed.AuthorityKeyIdentifier);

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

                issuingCaId ??= (await db.CaCertificates
                    .Where(ca => ca.CommunityId == CommunityId)
                    .OrderByDescending(ca => ca.ParentId)
                    .FirstOrDefaultAsync())?.Id;

                if (issuingCaId == null)
                {
                    importErrors.Add($"{fileName}: No CA found to issue under");
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
            ToastService.ShowSuccess($"Imported '{fileName}'");
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

                // If no match found, try to find any intermediate, then root
                if (issuingCaId == null)
                {
                    var firstCa = await db.CaCertificates
                        .Where(ca => ca.CommunityId == CommunityId)
                        .OrderByDescending(ca => ca.ParentId) // prefer intermediates
                        .FirstOrDefaultAsync();

                    issuingCaId = firstCa?.Id;
                }

                if (issuingCaId == null)
                {
                    importError = "No CA certificate found in this community. Import a CA certificate first.";
                    confirmDialogHidden = true;
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

            ToastService.ShowSuccess($"Certificate '{importName}' imported successfully.");
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
        ToastService.ShowSuccess(
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

    public class CommunityOption
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }
}

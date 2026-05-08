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
using Sigil.Common.Services.Jobs;
using Sigil.Common.Services.Signing;
using Sigil.Common.ViewModels;
using Sigil.Gcp;
using Sigil.UI.Services;
using Sigil.Vault;

namespace Sigil.UI.Components.Pages;

public partial class CertificateExplorer : IDisposable
{
    [Parameter] public int CommunityId { get; set; }
    [SupplyParameterFromQuery(Name = "thumbprint")] public string? SelectedThumbprint { get; set; }

    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private CertificateParsingService ParsingService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private Asn1ParsingService Asn1Parser { get; set; } = null!;
    [Inject] private CrlImportService CrlImporter { get; set; } = null!;
    [Inject] private ChainValidationService ChainValidator { get; set; } = null!;
    [Inject] private CertificateIssuanceService IssuanceService { get; set; } = null!;
    [Inject] private CertificateExportService ExportService { get; set; } = null!;
    [Inject] private CertificateManagementService ManagementService { get; set; } = null!;
    [Inject] private CertificatePublishingService PublishingService { get; set; } = null!;
    [Inject] private ISigningProvider SigningProvider { get; set; } = null!;
    [Inject] private VaultTransitSigningProvider VaultTransitProvider { get; set; } = null!;
    [Inject] private GcpKmsSigningProvider GcpKmsProvider { get; set; } = null!;
    [Inject] private IHttpClientFactory HttpClientFactory { get; set; } = null!;
    [Inject] private IJSRuntime JS { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;
    [Inject] private CrlGenerationService CrlGenService { get; set; } = null!;
    [Inject] private TimeDisplayService TimeDisplay { get; set; } = null!;

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
    private bool selectedNodeHasRemoteKey;
    private bool selectedNodeCanSign => selectedNodeHasPrivateKey || selectedNodeHasRemoteKey;
    private bool selectedNodeAutoRenew = true;
    private bool isGeneratingCrl;
    private bool isPublishingAia;
    private List<string> subjectAltNames = new();
    private FluentTreeItem? selectedTreeItem;
    private int treeVersion;
    private bool isLoadingTree;
    private bool isRevalidating;
    private bool isValidatingOnline;
    private bool pendingHighlight;
    private Dictionary<string, ChainValidationResult> communityValidations = new();

    // Rename state
    private bool isRenaming;
    private string renamingValue = string.Empty;

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
    private List<IssuanceUrlEntry> issuanceCdpUrls = new();
    private List<IssuanceUrlEntry> issuanceAiaUrls = new();
    private List<IssuanceSanEntry> issuanceSans = new();
    private string issuancePfxPassword = string.Empty;
    private string issuanceKeyStorage = "local"; // "local" or "vault-transit"
    private bool isRenewMode;
    private List<IssuanceSanEntry> renewalSans = new();
    private string renewalSubjectDn = string.Empty;

    // Revoke dialog
    private bool revokeDialogHidden = true;
    private bool isRevoking;
    private RevokeReasonOption selectedRevokeReason = null!;
    private static readonly List<RevokeReasonOption> revokeReasonOptions = new()
    {
        new(0, "Unspecified"),
        new(1, "Key Compromise"),
        new(2, "CA Compromise"),
        new(3, "Affiliation Changed"),
        new(4, "Superseded"),
        new(5, "Cessation of Operation"),
        new(9, "Privilege Withdrawn"),
    };

    // Re-sign dialog
    private bool resignDialogHidden = true;
    private bool isResigning;
    private DateTime? resignNotBefore = DateTime.UtcNow;
    private DateTime? resignNotAfter = DateTime.UtcNow.AddYears(5);
    private string resignPfxPassword = string.Empty;

    protected override async Task OnInitializedAsync()
    {
        TimeDisplay.OnChanged += StateHasChanged;
        await using var db = await DbFactory.CreateDbContextAsync();

        communityList = await db.Communities
            .OrderBy(c => c.Name)
            .Select(c => new CommunityOption
            {
                Id = c.Id,
                Name = c.Name,
                BaseUrls = c.BaseUrls.OrderBy(bu => bu.SortOrder)
                    .Select(bu => new BaseUrlViewModel { Url = bu.Url, PublishingBasePath = bu.PublishingBasePath })
                    .ToList()
            })
            .ToListAsync();

        if (CommunityId > 0)
        {
            selectedCommunity = communityList.FirstOrDefault(c => c.Id == CommunityId);
            await LoadCommunityTreeAsync(CommunityId);

            // Auto-select cert if thumbprint was provided via query string
            if (!string.IsNullOrEmpty(SelectedThumbprint))
            {
                var node = FindNodeByThumbprint(treeNodes, SelectedThumbprint);
                if (node != null)
                {
                    await SelectNode(node);
                    pendingHighlight = true;
                }

                // Clear the query string so it doesn't linger as the user navigates
                SelectedThumbprint = null;
                Navigation.NavigateTo($"/explorer/{CommunityId}", replace: true);
            }
        }
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (pendingHighlight)
        {
            pendingHighlight = false;
            await UpdateTreeHighlightsAsync();
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
        isLoadingTree = true;
        StateHasChanged();

        var treeData = await ManagementService.GetCommunityTreeAsync(communityId);

        selectedCommunityName = treeData.CommunityName;
        communityValidations = treeData.Validations;
        treeNodes = treeData.TreeNodes;

        treeVersion++;
        selectedTreeItem = null;
        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        chainValidation = null;
        asn1Root = null;
        subjectAltNames.Clear();
        isLoadingTree = false;
    }


    // --- Tree selection ---

    private async Task OnTreeItemSelected(FluentTreeItem? item)
    {
        selectedTreeItem = item;
        isRenaming = false;

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
        selectedNodeHasRemoteKey = false;
        selectedNodeAutoRenew = true;
        chainValidation = null;
        asn1Root = null;
        subjectAltNames.Clear();
        CloseIssuerDetails();

        // CRL selection still uses DbFactory (CRL detail view is UI-specific)
        if (node.EntityType == "Crl")
        {
            await using var db = await DbFactory.CreateDbContextAsync();
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
                    Thumbprint = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(crl.RawBytes)),
                    AuthorityKeyIdentifier = ExtractCrlAki(crl.RawBytes),
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

                asn1Root = Asn1Parser.Parse(crl.RawBytes);
            }

            return;
        }

        var details = await ManagementService.GetNodeDetailsAsync(node.Id, node.EntityType);
        selectedNodeHasPrivateKey = details.HasPrivateKey;
        selectedNodeHasRemoteKey = details.HasRemoteKey;
        selectedNodeAutoRenew = details.AutoRenew;

        if (!string.IsNullOrEmpty(details.Pem))
        {
            try
            {
                selectedCert = X509Certificate2.CreateFromPem(details.Pem);
                asn1Root = Asn1Parser.ParsePem(details.Pem);

                if (!string.IsNullOrEmpty(node.Thumbprint)
                    && communityValidations.TryGetValue(node.Thumbprint, out var cached))
                {
                    chainValidation = cached;
                }
                else
                {
                    if (node.EntityType == "CaCertificate")
                        chainValidation = await ChainValidator.ValidateCaCertificateAsync(node.Id);
                    else
                        chainValidation = await ChainValidator.ValidateIssuedCertificateAsync(node.Id);
                }
            }
            catch { }
        }

        if (!string.IsNullOrEmpty(details.SubjectAltNames))
        {
            subjectAltNames = details.SubjectAltNames.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
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

            if (!string.IsNullOrEmpty(selectedNode.Thumbprint) && chainValidation != null)
            {
                communityValidations[selectedNode.Thumbprint] = chainValidation;
                selectedNode.Status = CertificateManagementService.DeriveStatus(
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

    private async Task GenerateCrlForSelectedAsync()
    {
        if (isGeneratingCrl || selectedNode == null) return;
        if (selectedNode.CertificateRole is not ("RootCA" or "IntermediateCA")) return;

        isGeneratingCrl = true;
        StateHasChanged();

        try
        {
            var result = await CrlGenService.GenerateCrlAsync(selectedNode.Id);
            if (result.IsSuccess)
            {
                ToastService.ShowSuccess($"CRL #{result.CrlNumber} generated ({result.RevokedCount} revoked certs)");
                await LoadCommunityTreeAsync(CommunityId);
            }
            else
            {
                ToastService.ShowCopyableError($"CRL generation failed: {result.Error}");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"CRL generation failed: {ex.Message}");
        }
        finally
        {
            isGeneratingCrl = false;
            StateHasChanged();
        }
    }

    private async Task PublishAiaForSelectedAsync()
    {
        if (isPublishingAia || selectedNode == null) return;
        if (selectedNode.CertificateRole is not ("RootCA" or "IntermediateCA")) return;

        isPublishingAia = true;
        StateHasChanged();

        try
        {
            var result = await PublishingService.PublishAiaCertificateAsync(selectedNode.Id);
            if (result.Success)
                ToastService.ShowSuccess($"Published certificate to {result.PublishedCount} endpoint(s)");
            else if (result.Error?.Contains("publishing paths") == true)
                ToastService.ShowWarning(result.Error);
            else
                ToastService.ShowCopyableError(result.Error ?? "AIA publish failed.");
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"AIA publish failed: {ex.Message}");
        }
        finally
        {
            isPublishingAia = false;
            StateHasChanged();
        }
    }

    private async Task EnsureIssuerPublishedAsync(int issuingCaId)
    {
        try
        {
            await PublishingService.EnsureIssuerPublishedAsync(issuingCaId);
        }
        catch
        {
        }
    }

    private async Task ValidateOnlineAsync()
    {
        if (selectedNode == null || selectedNode.EntityType == "Crl") return;

        isValidatingOnline = true;
        StateHasChanged();

        try
        {
            if (selectedNode.EntityType == "CaCertificate")
                chainValidation = await ChainValidator.ValidateCaCertificateOnlineAsync(selectedNode.Id);
            else
                chainValidation = await ChainValidator.ValidateIssuedCertificateOnlineAsync(selectedNode.Id);

            if (!string.IsNullOrEmpty(selectedNode.Thumbprint) && chainValidation != null)
            {
                communityValidations[selectedNode.Thumbprint] = chainValidation;
                selectedNode.Status = CertificateManagementService.DeriveStatus(
                    selectedNode.Thumbprint, selectedNode.NotAfter, false, communityValidations);
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Online validation failed: {ex.Message}");
        }
        finally
        {
            isValidatingOnline = false;
            StateHasChanged();
        }
    }

    // --- Rename Methods ---

    private void StartRename()
    {
        if (selectedNode == null) return;
        renamingValue = selectedNode.Name;
        isRenaming = true;
    }

    private void CancelRename()
    {
        isRenaming = false;
    }

    private async Task OnRenameKeyDown(Microsoft.AspNetCore.Components.Web.KeyboardEventArgs e)
    {
        if (e.Key == "Enter") await SaveRenameAsync();
        else if (e.Key == "Escape") CancelRename();
    }

    private async Task SaveRenameAsync()
    {
        if (selectedNode == null || string.IsNullOrWhiteSpace(renamingValue)) return;

        var trimmed = renamingValue.Trim();
        if (trimmed == selectedNode.Name)
        {
            isRenaming = false;
            return;
        }

        var result = await ManagementService.RenameAsync(selectedNode.Id, selectedNode.EntityType, trimmed);
        if (result.Success)
            selectedNode.Name = trimmed;

        isRenaming = false;
        StateHasChanged();
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

    private async Task CopyPrivateKeyAsync()
    {
        if (selectedNode == null) return;

        var result = await ExportService.ExportPrivateKeyPemAsync(
            selectedNode.Id, selectedNode.EntityType);

        if (!result.Success)
        {
            ToastService.ShowError(result.Error ?? "Failed to export private key.");
            return;
        }

        await JS.InvokeVoidAsync("sigilCopyText", result.Pem);
        ToastService.ShowSuccess("Private key copied to clipboard (PKCS#8 PEM)");
    }

    private async Task CopyCertBase64Async()
    {
        if (selectedNode == null) return;

        var result = await ExportService.ExportCertificateDerBase64Async(
            selectedNode.Id, selectedNode.EntityType);

        if (!result.Success)
        {
            ToastService.ShowError(result.Error ?? "Failed to export certificate.");
            return;
        }

        await JS.InvokeVoidAsync("sigilCopyText", result.Pem);
        ToastService.ShowSuccess("Certificate base64 (DER) copied to clipboard");
    }

    private async Task<int?> FindCaBySkiAsync(SigilDbContext db, string authorityKeyIdentifier)
    {
        return await CertificateManagementService.FindCaBySkiInternalAsync(db, CommunityId, authorityKeyIdentifier);
    }

    private async Task<int?> FindCaByDnAndSignatureAsync(SigilDbContext db, X509Certificate2 cert)
    {
        return await CertificateManagementService.FindCaByDnAndSignatureInternalAsync(db, CommunityId, cert);
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

    // --- Auto Renew ---

    private async Task ToggleAutoRenewAsync(bool enabled)
    {
        if (selectedNode == null) return;

        await ManagementService.SetAutoRenewAsync(selectedNode.Id, selectedNode.EntityType, enabled);
        selectedNodeAutoRenew = enabled;
    }

    // --- Delete & Move ---

    private async Task ArchiveSelectedAsync()
    {
        if (selectedNode == null) return;

        var dialog = await DialogService.ShowConfirmationAsync(
            $"Archive '{selectedNode.Name}'? It will be hidden from the tree but preserved in the database.",
            "Archive", "Cancel", "Confirm Archive");
        var result = await dialog.Result;

        if (result.Cancelled) return;

        var archiveResult = await ManagementService.ArchiveAsync(selectedNode.Id, selectedNode.EntityType);
        if (archiveResult.Success)
            ToastService.ShowCopyableSuccess($"Archived '{selectedNode.Name}'");
        else
            ToastService.ShowCopyableError(archiveResult.Error ?? "Archive failed.");

        await ClearSelectionAndReloadTreeAsync();
    }

    private async Task DeleteSelectedAsync()
    {
        if (selectedNode == null) return;

        var dialog = await DialogService.ShowConfirmationAsync(
            $"Permanently delete '{selectedNode.Name}'? This cannot be undone.",
            "Delete Forever", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (result.Cancelled) return;

        var deleteResult = await ManagementService.DeleteAsync(
            selectedNode.Id, selectedNode.EntityType, DeleteRemoteKeyAsync);

        if (deleteResult.Success)
        {
            ToastService.ShowCopyableSuccess($"Permanently deleted '{selectedNode.Name}'");
            await ClearSelectionAndReloadTreeAsync();
        }
        else
        {
            ToastService.ShowCopyableError(deleteResult.Error ?? "Delete failed.");
        }
    }

    /// <summary>
    /// Deletes a remote signing key (Vault Transit or GCP KMS) if the StoreProviderHint indicates one.
    /// </summary>
    private async Task DeleteRemoteKeyAsync(string? storeProviderHint)
    {
        if (string.IsNullOrEmpty(storeProviderHint))
            return;

        try
        {
            if (storeProviderHint.StartsWith("vault-transit:"))
            {
                var keyName = storeProviderHint["vault-transit:".Length..];
                if (!string.IsNullOrEmpty(keyName))
                    await VaultTransitProvider.DeleteKeyAsync(keyName);
            }
            else if (storeProviderHint.StartsWith("gcp-kms:"))
            {
                var keyId = storeProviderHint["gcp-kms:".Length..];
                if (!string.IsNullOrEmpty(keyId))
                    await GcpKmsProvider.DestroyKeyVersionAsync(keyId);
            }
        }
        catch (Exception ex)
        {
            // Log but don't block the DB delete — the remote key is orphaned but that's better
            // than leaving the DB record pointing to a deleted cert
            ToastService.ShowCopyableError($"Remote key cleanup failed: {ex.Message}");
        }
    }

    private async Task ClearSelectionAndReloadTreeAsync()
    {
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

        var moveResult = await ManagementService.MoveAsync(
            selectedNode.Id, selectedNode.EntityType, moveTargetCommunity.Id);

        moveDialogHidden = true;

        if (moveResult.Success)
        {
            ToastService.ShowCopyableSuccess($"Moved '{selectedNode.Name}' to '{moveTargetCommunity.Name}'");
            selectedNode = null;
            selectedCert?.Dispose();
            selectedCert = null;
            chainValidation = null;
            await LoadCommunityTreeAsync(CommunityId);
        }
        else
        {
            ToastService.ShowCopyableError(moveResult.Error ?? "Move failed.");
        }
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

            // Validate issuer relationship if a parent CA was matched
            if (matchedParentCaId.HasValue)
            {
                var parentCaEntity = await db.CaCertificates.FindAsync(matchedParentCaId.Value);
                if (parentCaEntity != null)
                {
                    using var parentCert = X509Certificate2.CreateFromPem(parentCaEntity.X509CertificatePem);
                    var issuerError = CertificateIssuanceService.VerifyIssuedBy(cert, parentCert);
                    if (issuerError != null)
                    {
                        importError = $"Cannot link to '{parentCaEntity.Name}': {issuerError}";
                        confirmDialogHidden = true;
                        return;
                    }
                }
            }

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
        var nextUpdateStr = result.NextUpdate.HasValue ? TimeDisplay.FormatShort(result.NextUpdate.Value) : "unknown";
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

        // Validate the cert was actually signed by the selected CA
        var selectedCaEntity = await db.CaCertificates.FindAsync(selectedCaForAssignment!.Id);
        if (selectedCaEntity != null)
        {
            using var caCert = X509Certificate2.CreateFromPem(selectedCaEntity.X509CertificatePem);
            var issuerError = CertificateIssuanceService.VerifyIssuedBy(cert, caCert);
            if (issuerError != null)
            {
                parsed.Certificate.Dispose();
                ToastService.ShowCopyableError($"Cannot assign under '{selectedCaEntity.Name}': {issuerError}");
                return;
            }
        }

        // New cert — assign under selected CA
        if (parsed.DetectedRole is DetectedCertRole.RootCa or DetectedCertRole.IntermediateCa)
        {
            db.CaCertificates.Add(new CaCertificate
            {
                CommunityId = CommunityId,
                ParentId = selectedCaForAssignment.Id,
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
        isRenewMode = false;
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
        issuanceKeyStorage = "local";
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

        var cdpTemplate = template.CdpUrlTemplate;
        if (template.IncludeCdp && string.IsNullOrWhiteSpace(cdpTemplate))
            cdpTemplate = "{BaseUrl}/crls/{CAName}.crl";
        issuanceCdpUrls = ExpandUrlTemplates(cdpTemplate)
            .Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        var aiaTemplate = template.AiaUrlTemplate;
        if (template.IncludeAia && string.IsNullOrWhiteSpace(aiaTemplate))
            aiaTemplate = "{BaseUrl}/certs/{CAName}.cer";
        issuanceAiaUrls = ExpandUrlTemplates(aiaTemplate)
            .Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        if (isRenewMode)
        {
            issuanceSubjectDn = renewalSubjectDn;
            issuanceSans = renewalSans.Select(s => new IssuanceSanEntry { Type = s.Type, Value = s.Value }).ToList();
        }
        else
        {
            if (string.IsNullOrWhiteSpace(issuanceSubjectDn))
                issuanceSubjectDn = template.SubjectTemplate ?? string.Empty;

            var hasUserSans = issuanceSans.Any(s => !string.IsNullOrWhiteSpace(s.Value));
            if (!hasUserSans)
            {
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
        if (isIssuing) return;
        if (selectedTemplate == null || string.IsNullOrWhiteSpace(issuanceSubjectDn)) return;

        isIssuing = true;
        StateHasChanged();

        var cdpUrls = selectedTemplate.IncludeCdp
            ? issuanceCdpUrls.Where(u => !string.IsNullOrWhiteSpace(u.Value)).Select(u => u.Value).ToList()
            : new List<string>();
        var aiaUrls = selectedTemplate.IncludeAia
            ? issuanceAiaUrls.Where(u => !string.IsNullOrWhiteSpace(u.Value)).Select(u => u.Value).ToList()
            : new List<string>();

        // Ensure the issuing CA's cert and CRL are published before validating URLs
        if (issuingCaIdForIssuance.HasValue)
        {
            await EnsureIssuerPublishedAsync(issuingCaIdForIssuance.Value);
        }

        // Warn about missing CDP/AIA when the template expects them
        var warnings = new List<string>();
        if (selectedTemplate.IncludeCdp && cdpUrls.Count == 0)
            warnings.Add("CRL Distribution Point (CDP) URLs are empty but the template has CDP enabled.");
        if (selectedTemplate.IncludeAia && aiaUrls.Count == 0)
            warnings.Add("Authority Information Access (AIA) URLs are empty but the template has AIA enabled.");

        // Validate that provided CDP and AIA URLs resolve
        var unreachableUrls = await ValidateEndpointUrlsAsync(cdpUrls, aiaUrls);
        foreach (var u in unreachableUrls)
            warnings.Add($"{u.Url}: {u.Error}");

        if (warnings.Count > 0)
        {
            var warningList = string.Join("\n", warnings.Select(w => $"  \u2022 {w}"));
            var dialog = await DialogService.ShowConfirmationAsync(
                $"The following issue(s) were detected:\n\n{warningList}\n\nCertificates issued without valid CDP/AIA endpoints may cause chain validation failures. Continue anyway?",
                "Issue Anyway", "Cancel", "Endpoint Warnings");
            var dialogResult = await dialog.Result;
            if (dialogResult.Cancelled)
            {
                isIssuing = false;
                return;
            }
        }

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
                CdpUrls = cdpUrls,
                AiaUrls = aiaUrls,
                NotBefore = issuanceNotBeforeNullable.HasValue ? new DateTimeOffset(issuanceNotBeforeNullable.Value, TimeSpan.Zero) : null,
                NotAfter = issuanceNotAfterNullable.HasValue ? new DateTimeOffset(issuanceNotAfterNullable.Value, TimeSpan.Zero) : null,
                PfxPassword = issuancePfxPassword,
                SigningProviderOverride = issuanceKeyStorage,
            };

            var result = await IssuanceService.IssueCertificateAsync(request);

            if (result.Success)
            {
                // Generate initial CRL for newly issued CA certificates
                if (result.EntityType == "CaCertificate" && result.EntityId.HasValue)
                {
                    var crlResult = await CrlGenService.GenerateCrlAsync(result.EntityId.Value);
                    if (!crlResult.IsSuccess)
                        ToastService.ShowWarning($"Initial CRL generation failed: {crlResult.Error}");
                }

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

    private async Task<List<(string Url, string Error)>> ValidateEndpointUrlsAsync(List<string> cdpUrls, List<string> aiaUrls)
    {
        var unreachable = new List<(string Url, string Error)>();
        var urlsToCheck = new List<(string Url, string Label)>();

        foreach (var url in cdpUrls)
            urlsToCheck.Add((url, "CDP"));
        foreach (var url in aiaUrls)
            urlsToCheck.Add((url, "AIA"));

        if (urlsToCheck.Count == 0) return unreachable;

        using var httpClient = HttpClientFactory.CreateClient("SigilCrl");
        httpClient.Timeout = TimeSpan.FromSeconds(5);

        var tasks = urlsToCheck.Select(async entry =>
        {
            try
            {
                using var response = await httpClient.SendAsync(
                    new HttpRequestMessage(HttpMethod.Head, entry.Url),
                    HttpCompletionOption.ResponseHeadersRead);

                if (!response.IsSuccessStatusCode)
                {
                    return (entry.Url, Error: $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
                }

                return (entry.Url, Error: (string?)null)!;
            }
            catch (TaskCanceledException)
            {
                return (entry.Url, Error: "Connection timed out");
            }
            catch (HttpRequestException ex)
            {
                return (entry.Url, Error: ex.InnerException?.Message ?? ex.Message);
            }
        });

        var results = await Task.WhenAll(tasks);
        unreachable.AddRange(results.Where(r => r.Error != null)!);

        return unreachable;
    }

    private async Task ShowSimilarDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        renewalSubjectDn = selectedCert.Subject;
        renewalSans.Clear();
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
                renewalSans.Add(entry);
            }
        }

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
            issuingCaId = null;
            issuingCaName = null;
        }

        isRenewMode = true;
        await ShowIssuanceDialog(issuingCaId, issuingCaName);
        isRenewMode = true;

        var targetType = selectedNode.CertificateRole switch
        {
            "RootCA" => CertificateType.RootCa,
            "IntermediateCA" => CertificateType.IntermediateCa,
            "EndEntity" => CertificateType.EndEntityClient,
            _ => CertificateType.EndEntityClient
        };

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

        if (selectedTemplate == null || selectedTemplate.CertificateType != targetType)
        {
            var match = availableTemplates.FirstOrDefault(t => t.CertificateType == targetType)
                        ?? availableTemplates.FirstOrDefault();
            if (match != null)
            {
                selectedTemplate = match;
            }
        }

        OnTemplateSelected(selectedTemplate);

        issuanceCertName = selectedNode.Name;

        var cdpUrls = ExtractExtensionUrls(selectedCert, "2.5.29.31");
        if (cdpUrls.Count > 0)
            issuanceCdpUrls = cdpUrls.Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        var aiaUrls = ExtractExtensionUrls(selectedCert, "1.3.6.1.5.5.7.1.1");
        if (aiaUrls.Count > 0)
            issuanceAiaUrls = aiaUrls.Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        isRenewMode = false;
    }

    private static List<string> ExtractExtensionUrls(X509Certificate2? cert, string oid)
    {
        var urls = new List<string>();
        if (cert == null) return urls;

        var ext = cert.Extensions[oid];
        if (ext == null) return urls;

        var data = ext.RawData;
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == 0x86)
            {
                var len = data[i + 1];
                if (i + 2 + len <= data.Length)
                {
                    urls.Add(System.Text.Encoding.ASCII.GetString(data, i + 2, len));
                    i += 1 + len;
                }
            }
        }

        return urls;
    }

    private async Task ShowRenewDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        // Extract SANs and subject from existing cert BEFORE opening the dialog,
        // so they survive template selection changes
        renewalSubjectDn = selectedCert.Subject;
        renewalSans.Clear();
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
                renewalSans.Add(entry);
            }
        }

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
            issuingCaId = null;
            issuingCaName = null;
        }

        // Set renewal mode BEFORE opening the dialog so OnTemplateSelected preserves SANs
        isRenewMode = true;
        await ShowIssuanceDialog(issuingCaId, issuingCaName);
        isRenewMode = true; // ShowIssuanceDialog resets it — restore

        // Pre-select a template matching the original cert's role
        var targetType = selectedNode.CertificateRole switch
        {
            "RootCA" => CertificateType.RootCa,
            "IntermediateCA" => CertificateType.IntermediateCa,
            "EndEntity" => CertificateType.EndEntityClient,
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
            }
        }

        // Always call OnTemplateSelected with isRenewMode=true to restore subject/SANs
        OnTemplateSelected(selectedTemplate);

        issuanceCertName = selectedNode.Name + " (renewed)";
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

    private List<string> ExpandUrlTemplates(string? template)
    {
        if (string.IsNullOrWhiteSpace(template)) return new();

        var baseUrls = selectedCommunity?.BaseUrls ?? new();
        if (baseUrls.Count == 0)
        {
            var result = template;
            if (issuingCaNameForIssuance != null)
                result = result.Replace("{CAName}", issuingCaNameForIssuance, StringComparison.OrdinalIgnoreCase);
            return string.IsNullOrWhiteSpace(result) ? new() : new() { result };
        }

        var expanded = new List<string>();
        foreach (var baseUrl in baseUrls)
        {
            var result = template
                .Replace("{BaseUrl}", baseUrl.Url.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
            if (issuingCaNameForIssuance != null)
                result = result.Replace("{CAName}", issuingCaNameForIssuance, StringComparison.OrdinalIgnoreCase);
            expanded.Add(result);
        }

        return expanded;
    }

    private static string? ExtractCrlAki(byte[] crlBytes)
    {
        try
        {
            var crlParser = new Org.BouncyCastle.X509.X509CrlParser();
            var crl = crlParser.ReadCrl(crlBytes);
            var akiOctets = crl.GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier);
            if (akiOctets == null) return null;

            var aki = Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier.GetInstance(
                Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(akiOctets.GetOctets()));
            var keyId = aki.GetKeyIdentifier();
            return keyId != null ? Convert.ToHexString(keyId) : null;
        }
        catch
        {
            return null;
        }
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
        public List<BaseUrlViewModel> BaseUrls { get; set; } = new();
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

    public class IssuanceUrlEntry
    {
        public string Value { get; set; } = string.Empty;
    }

    private void ShowRevokeDialog()
    {
        if (selectedNode == null) return;
        selectedRevokeReason = revokeReasonOptions[0];
        isRevoking = false;
        revokeDialogHidden = false;
    }

    private async Task RevokeCertificateAsync()
    {
        if (selectedNode == null) return;

        isRevoking = true;
        StateHasChanged();

        try
        {
            var revokeResult = await ManagementService.RevokeAsync(
                selectedNode.Id, selectedNode.EntityType, selectedRevokeReason.Code);

            revokeDialogHidden = true;

            if (revokeResult.Success)
            {
                if (revokeResult.CrlNumber.HasValue)
                {
                    ToastService.ShowCopyableSuccess(
                        $"Certificate '{selectedNode.Name}' revoked (reason: {selectedRevokeReason.Label}). CRL #{revokeResult.CrlNumber} generated with {revokeResult.RevokedCount} revocation(s).");
                }
                else
                {
                    ToastService.ShowCopyableSuccess(
                        $"Certificate '{selectedNode.Name}' revoked (reason: {selectedRevokeReason.Label}).");
                }

                if (!string.IsNullOrEmpty(revokeResult.Error))
                    ToastService.ShowCopyableError(revokeResult.Error);
            }
            else
            {
                ToastService.ShowCopyableError(revokeResult.Error ?? "Revocation failed.");
            }

            await LoadCommunityTreeAsync(CommunityId);
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Revocation failed: {ex.Message}");
        }
        finally
        {
            isRevoking = false;
            StateHasChanged();
        }
    }

    public record RevokeReasonOption(int Code, string Label);

    public void Dispose()
    {
        TimeDisplay.OnChanged -= StateHasChanged;
    }
}

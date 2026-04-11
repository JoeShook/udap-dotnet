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
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.UI.Services;

namespace Sigil.UI.Components.Pages;

public partial class Templates
{
    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    private List<CertificateTemplate> templates = new();
    private bool dialogHidden = true;
    private bool isEditing;
    private int? editingId;

    // Form fields
    private string editName = string.Empty;
    private string editDescription = string.Empty;
    private CertificateType editCertType = CertificateType.EndEntityClient;
    private int editValidityDays = 365;
    private string editKeyAlgorithm = "RSA";
    private int editKeySize = 2048;
    private string editEcdsaCurve = "nistP384";
    private string editHashAlgorithm = "SHA256";
    private int editKeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature;
    private bool editIsKeyUsageCritical = true;
    private string editEkuOids = string.Empty;
    private string editCustomEkuOids = string.Empty;
    private HashSet<string> editSelectedEkuOids = new();
    private bool editIsEkuCritical;
    private bool editIsBasicConstraintsCa;
    private bool editIsBasicConstraintsCritical = true;
    private int? editPathLengthConstraint;
    private string editSubjectTemplate = string.Empty;
    private bool editIncludeCdp;
    private string editCdpUrlTemplate = string.Empty;
    private bool editIncludeAia;
    private string editAiaUrlTemplate = string.Empty;
    private bool editSanUri;
    private bool editSanDns;
    private bool editSanEmail;
    private bool editSanIp;

    // Options for selects
    private static readonly CertificateType[] certTypes = Enum.GetValues<CertificateType>();
    private static readonly string[] keyAlgorithms = ["RSA", "ECDSA"];
    private static readonly int[] rsaKeySizes = [2048, 3072, 4096];
    private static readonly string[] ecdsaCurves = ["nistP256", "nistP384", "nistP521"];
    private static readonly string[] hashAlgorithms = ["SHA256", "SHA384", "SHA512"];

    private static readonly (X509KeyUsageFlags Flag, string Label)[] keyUsageOptions =
    [
        (X509KeyUsageFlags.DigitalSignature, "Digital Signature"),
        (X509KeyUsageFlags.KeyCertSign, "Certificate Signing"),
        (X509KeyUsageFlags.CrlSign, "CRL Signing"),
        (X509KeyUsageFlags.KeyEncipherment, "Key Encipherment"),
        (X509KeyUsageFlags.DataEncipherment, "Data Encipherment"),
        (X509KeyUsageFlags.KeyAgreement, "Key Agreement"),
        (X509KeyUsageFlags.NonRepudiation, "Non-Repudiation"),
    ];

    private static readonly (string Oid, string Name)[] ekuOptions =
    [
        ("1.3.6.1.5.5.7.3.1", "TLS Server Authentication"),
        ("1.3.6.1.5.5.7.3.2", "TLS Client Authentication"),
        ("1.3.6.1.5.5.7.3.3", "Code Signing"),
        ("1.3.6.1.5.5.7.3.4", "Email Protection (S/MIME)"),
        ("1.3.6.1.5.5.7.3.8", "Time Stamping"),
        ("1.3.6.1.5.5.7.3.9", "OCSP Signing"),
        ("1.3.6.1.4.1.311.10.3.12", "Document Signing"),
        ("1.3.6.1.5.5.7.3.17", "IPSEC IKE Intermediate"),
        ("2.16.840.1.113730.4.1", "Netscape SGC"),
        ("1.3.6.1.4.1.311.10.3.3", "Microsoft SGC"),
    ];

    protected override async Task OnInitializedAsync()
    {
        await LoadTemplatesAsync();
    }

    private async Task LoadTemplatesAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();
        templates = await db.CertificateTemplates
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync();
    }

    private void ShowAddDialog()
    {
        isEditing = false;
        editingId = null;
        ResetForm();
        dialogHidden = false;
    }

    private void ShowEditDialog(CertificateTemplate t)
    {
        isEditing = true;
        editingId = t.Id;
        PopulateForm(t);
        dialogHidden = false;
    }

    private void ResetForm()
    {
        editName = string.Empty;
        editDescription = string.Empty;
        editCertType = CertificateType.EndEntityClient;
        editValidityDays = 365;
        editKeyAlgorithm = "RSA";
        editKeySize = 2048;
        editEcdsaCurve = "nistP384";
        editHashAlgorithm = "SHA256";
        editKeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature;
        editIsKeyUsageCritical = true;
        editEkuOids = string.Empty;
        editCustomEkuOids = string.Empty;
        editSelectedEkuOids.Clear();
        editIsEkuCritical = false;
        editIsBasicConstraintsCa = false;
        editIsBasicConstraintsCritical = true;
        editPathLengthConstraint = null;
        editSubjectTemplate = string.Empty;
        editIncludeCdp = false;
        editCdpUrlTemplate = string.Empty;
        editIncludeAia = false;
        editAiaUrlTemplate = string.Empty;
        editSanUri = false;
        editSanDns = false;
        editSanEmail = false;
        editSanIp = false;
    }

    private void PopulateForm(CertificateTemplate t)
    {
        editName = t.Name;
        editDescription = t.Description ?? string.Empty;
        editCertType = t.CertificateType;
        editValidityDays = t.ValidityDays;
        editKeyAlgorithm = t.KeyAlgorithm;
        editKeySize = t.KeySize;
        editEcdsaCurve = t.EcdsaCurve ?? "nistP384";
        editHashAlgorithm = t.HashAlgorithm;
        editKeyUsageFlags = t.KeyUsageFlags;
        editIsKeyUsageCritical = t.IsKeyUsageCritical;
        editEkuOids = t.ExtendedKeyUsageOids ?? string.Empty;
        // Split stored OIDs into known (checkboxes) and custom (text field)
        editSelectedEkuOids.Clear();
        editCustomEkuOids = string.Empty;
        if (!string.IsNullOrWhiteSpace(editEkuOids))
        {
            var knownOids = ekuOptions.Select(e => e.Oid).ToHashSet();
            var customParts = new List<string>();
            foreach (var oid in editEkuOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (knownOids.Contains(oid))
                    editSelectedEkuOids.Add(oid);
                else
                    customParts.Add(oid);
            }
            editCustomEkuOids = string.Join(";", customParts);
        }
        editIsEkuCritical = t.IsExtendedKeyUsageCritical;
        editIsBasicConstraintsCa = t.IsBasicConstraintsCa;
        editIsBasicConstraintsCritical = t.IsBasicConstraintsCritical;
        editPathLengthConstraint = t.PathLengthConstraint;
        editSubjectTemplate = t.SubjectTemplate ?? string.Empty;
        editIncludeCdp = t.IncludeCdp;
        editCdpUrlTemplate = t.CdpUrlTemplate ?? string.Empty;
        editIncludeAia = t.IncludeAia;
        editAiaUrlTemplate = t.AiaUrlTemplate ?? string.Empty;

        var sanTypes = (t.SubjectAltNameTypes ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries);
        editSanUri = sanTypes.Contains("URI", StringComparer.OrdinalIgnoreCase);
        editSanDns = sanTypes.Contains("DNS", StringComparer.OrdinalIgnoreCase);
        editSanEmail = sanTypes.Contains("Email", StringComparer.OrdinalIgnoreCase);
        editSanIp = sanTypes.Contains("IP", StringComparer.OrdinalIgnoreCase);
    }

    private CertificateTemplate BuildEntityFromForm(CertificateTemplate? existing = null)
    {
        var entity = existing ?? new CertificateTemplate();
        entity.Name = editName.Trim();
        entity.Description = string.IsNullOrWhiteSpace(editDescription) ? null : editDescription.Trim();
        entity.CertificateType = editCertType;
        entity.ValidityDays = editValidityDays;
        entity.KeyAlgorithm = editKeyAlgorithm;
        entity.KeySize = editKeyAlgorithm == "RSA" ? editKeySize : 0;
        entity.EcdsaCurve = editKeyAlgorithm == "ECDSA" ? editEcdsaCurve : null;
        entity.HashAlgorithm = editHashAlgorithm;
        entity.KeyUsageFlags = editKeyUsageFlags;
        entity.IsKeyUsageCritical = editIsKeyUsageCritical;
        entity.ExtendedKeyUsageOids = string.IsNullOrWhiteSpace(editEkuOids) ? null : editEkuOids.Trim();
        entity.IsExtendedKeyUsageCritical = editIsEkuCritical;
        entity.IsBasicConstraintsCa = editIsBasicConstraintsCa;
        entity.IsBasicConstraintsCritical = editIsBasicConstraintsCritical;
        entity.PathLengthConstraint = editIsBasicConstraintsCa ? editPathLengthConstraint : null;
        entity.SubjectTemplate = string.IsNullOrWhiteSpace(editSubjectTemplate) ? null : editSubjectTemplate.Trim();
        entity.IncludeCdp = editIncludeCdp;
        entity.CdpUrlTemplate = editIncludeCdp && !string.IsNullOrWhiteSpace(editCdpUrlTemplate) ? editCdpUrlTemplate.Trim() : null;
        entity.IncludeAia = editIncludeAia;
        entity.AiaUrlTemplate = editIncludeAia && !string.IsNullOrWhiteSpace(editAiaUrlTemplate) ? editAiaUrlTemplate.Trim() : null;

        var sanParts = new List<string>();
        if (editSanUri) sanParts.Add("URI");
        if (editSanDns) sanParts.Add("DNS");
        if (editSanEmail) sanParts.Add("Email");
        if (editSanIp) sanParts.Add("IP");
        entity.SubjectAltNameTypes = sanParts.Count > 0 ? string.Join(";", sanParts) : null;

        return entity;
    }

    private async Task SaveTemplateAsync()
    {
        if (string.IsNullOrWhiteSpace(editName)) return;

        await using var db = await DbFactory.CreateDbContextAsync();

        if (isEditing && editingId.HasValue)
        {
            var entity = await db.CertificateTemplates.FindAsync(editingId.Value);
            if (entity != null)
            {
                BuildEntityFromForm(entity);
                await db.SaveChangesAsync();
                ToastService.ShowCopyableSuccess($"Template '{entity.Name}' updated.");
            }
        }
        else
        {
            var entity = BuildEntityFromForm();
            db.CertificateTemplates.Add(entity);
            await db.SaveChangesAsync();
            ToastService.ShowCopyableSuccess($"Template '{entity.Name}' created.");
        }

        dialogHidden = true;
        await LoadTemplatesAsync();
    }

    private async Task CloneTemplateAsync(CertificateTemplate source)
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        var clone = new CertificateTemplate
        {
            Name = $"Copy of {source.Name}",
            Description = source.Description,
            CertificateType = source.CertificateType,
            KeyAlgorithm = source.KeyAlgorithm,
            KeySize = source.KeySize,
            ValidityDays = source.ValidityDays,
            KeyUsageFlags = source.KeyUsageFlags,
            IsKeyUsageCritical = source.IsKeyUsageCritical,
            ExtendedKeyUsageOids = source.ExtendedKeyUsageOids,
            IsExtendedKeyUsageCritical = source.IsExtendedKeyUsageCritical,
            IsBasicConstraintsCa = source.IsBasicConstraintsCa,
            IsBasicConstraintsCritical = source.IsBasicConstraintsCritical,
            PathLengthConstraint = source.PathLengthConstraint,
            EcdsaCurve = source.EcdsaCurve,
            HashAlgorithm = source.HashAlgorithm,
            SubjectTemplate = source.SubjectTemplate,
            IncludeCdp = source.IncludeCdp,
            CdpUrlTemplate = source.CdpUrlTemplate,
            IncludeAia = source.IncludeAia,
            AiaUrlTemplate = source.AiaUrlTemplate,
            SubjectAltNameTypes = source.SubjectAltNameTypes,
            IsPreset = false,
        };

        db.CertificateTemplates.Add(clone);
        await db.SaveChangesAsync();

        ToastService.ShowCopyableSuccess($"Template cloned as '{clone.Name}'.");
        await LoadTemplatesAsync();
    }

    private async Task DeleteTemplateAsync(CertificateTemplate template)
    {
        if (template.IsPreset) return;

        var dialog = await DialogService.ShowConfirmationAsync(
            $"Delete template '{template.Name}'?",
            "Delete", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            var entity = await db.CertificateTemplates.FindAsync(template.Id);
            if (entity != null)
            {
                db.CertificateTemplates.Remove(entity);
                await db.SaveChangesAsync();
                ToastService.ShowCopyableSuccess($"Template '{template.Name}' deleted.");
            }

            await LoadTemplatesAsync();
        }
    }

    private void ToggleKeyUsageFlag(X509KeyUsageFlags flag, bool enabled)
    {
        if (enabled)
            editKeyUsageFlags |= (int)flag;
        else
            editKeyUsageFlags &= ~(int)flag;
    }

    private bool IsEkuSelected(string oid) => editSelectedEkuOids.Contains(oid);

    private void ToggleEku(string oid, bool enabled)
    {
        if (enabled)
            editSelectedEkuOids.Add(oid);
        else
            editSelectedEkuOids.Remove(oid);
        SyncEkuOids();
    }

    private void SyncEkuOids()
    {
        var all = new List<string>(editSelectedEkuOids);

        // Add any custom OIDs
        if (!string.IsNullOrWhiteSpace(editCustomEkuOids))
        {
            foreach (var oid in editCustomEkuOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!all.Contains(oid))
                    all.Add(oid);
            }
        }

        editEkuOids = all.Count > 0 ? string.Join(";", all) : string.Empty;
    }

    private static string GetCertTypeLabel(CertificateType ct) => ct switch
    {
        CertificateType.RootCa => "Root CA",
        CertificateType.IntermediateCa => "Intermediate CA",
        CertificateType.EndEntityClient => "Client",
        CertificateType.EndEntityServer => "Server",
        _ => ct.ToString()
    };

    private static (string bg, string label) GetTypeBadge(CertificateType ct) => ct switch
    {
        CertificateType.RootCa => ("#8b5cf6", "Root CA"),
        CertificateType.IntermediateCa => ("#3b82f6", "Intermediate CA"),
        CertificateType.EndEntityClient => ("#10b981", "Client"),
        CertificateType.EndEntityServer => ("#f59e0b", "Server"),
        _ => ("#666", ct.ToString())
    };
}

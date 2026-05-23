#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.Common.Data.Entities;
using Sigil.Did.Services;

namespace Sigil.UI.Components.Pages;

public partial class DidTemplates
{
    [Inject] private DidTemplateService TemplateService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    private List<DidTemplate> templates = new();
    private bool dialogHidden = true;
    private bool isEditing;
    private int? editingId;
    private bool editingIsPreset;

    private string editName = string.Empty;
    private string editDescription = string.Empty;
    private string editMethod = "key";
    private string editKeyAlgorithm = "Ed25519";
    private string editDefaultPurposes = "assertionMethod;authentication";

    private static readonly string[] supportedMethods = ["key"];
    private static readonly string[] supportedAlgorithms = ["Ed25519"];

    protected override async Task OnInitializedAsync() => await LoadAsync();

    private async Task LoadAsync() => templates = await TemplateService.GetAllAsync();

    private void ShowAddDialog()
    {
        isEditing = false;
        editingId = null;
        editingIsPreset = false;
        editName = string.Empty;
        editDescription = string.Empty;
        editMethod = "key";
        editKeyAlgorithm = "Ed25519";
        editDefaultPurposes = "assertionMethod;authentication";
        dialogHidden = false;
    }

    private void ShowEditDialog(DidTemplate t)
    {
        isEditing = true;
        editingId = t.Id;
        editingIsPreset = t.IsPreset;
        editName = t.Name;
        editDescription = t.Description ?? string.Empty;
        editMethod = t.Method;
        editKeyAlgorithm = t.KeyAlgorithm;
        editDefaultPurposes = t.DefaultPurposes;
        dialogHidden = false;
    }

    private async Task SaveAsync()
    {
        if (string.IsNullOrWhiteSpace(editName)) return;

        var entity = new DidTemplate
        {
            Id = editingId ?? 0,
            Name = editName.Trim(),
            Description = string.IsNullOrWhiteSpace(editDescription) ? null : editDescription.Trim(),
            Method = editMethod,
            KeyAlgorithm = editKeyAlgorithm,
            DefaultPurposes = string.IsNullOrWhiteSpace(editDefaultPurposes)
                ? "assertionMethod;authentication"
                : editDefaultPurposes.Trim(),
            IsPreset = editingIsPreset,
        };

        try
        {
            await TemplateService.SaveAsync(entity);
            ToastService.ShowSuccess($"DID template '{entity.Name}' saved.");
            dialogHidden = true;
            await LoadAsync();
        }
        catch (Exception ex)
        {
            ToastService.ShowError($"Save failed: {ex.Message}");
        }
    }

    private async Task DeleteAsync(DidTemplate t)
    {
        if (t.IsPreset) return;

        var dialog = await DialogService.ShowConfirmationAsync(
            $"Delete DID template '{t.Name}'?",
            "Delete", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            await TemplateService.DeleteAsync(t.Id);
            ToastService.ShowSuccess($"DID template '{t.Name}' deleted.");
            await LoadAsync();
        }
    }
}

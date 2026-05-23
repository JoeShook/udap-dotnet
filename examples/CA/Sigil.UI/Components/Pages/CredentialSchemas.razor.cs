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
using Sigil.Vc.Services;

namespace Sigil.UI.Components.Pages;

public partial class CredentialSchemas
{
    [Inject] private CredentialSchemaService SchemaService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    private List<CredentialSchema> schemas = new();
    private bool dialogHidden = true;
    private bool isEditing;
    private int? editingId;
    private bool editingIsPreset;

    private string editName = string.Empty;
    private string editDescription = string.Empty;
    private string editTypeUri = string.Empty;
    private string editFormat = "jwt_vc";
    private int? editValidityDays = 365;
    private string editClaimsSchemaJson = DefaultSchema;
    private string saveError = string.Empty;

    private static readonly string[] supportedFormats = ["jwt_vc"];

    private const string DefaultSchema = """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "required": [],
          "properties": {},
          "additionalProperties": false
        }
        """;

    protected override async Task OnInitializedAsync() => await LoadAsync();

    private async Task LoadAsync() => schemas = await SchemaService.GetAllAsync();

    private void ShowAddDialog()
    {
        isEditing = false;
        editingId = null;
        editingIsPreset = false;
        editName = string.Empty;
        editDescription = string.Empty;
        editTypeUri = string.Empty;
        editFormat = "jwt_vc";
        editValidityDays = 365;
        editClaimsSchemaJson = DefaultSchema;
        saveError = string.Empty;
        dialogHidden = false;
    }

    private void ShowEditDialog(CredentialSchema s)
    {
        isEditing = true;
        editingId = s.Id;
        editingIsPreset = s.IsPreset;
        editName = s.Name;
        editDescription = s.Description ?? string.Empty;
        editTypeUri = s.TypeUri ?? string.Empty;
        editFormat = s.Format;
        editValidityDays = s.DefaultValidityDays;
        editClaimsSchemaJson = s.ClaimsSchemaJson;
        saveError = string.Empty;
        dialogHidden = false;
    }

    private async Task SaveAsync()
    {
        if (string.IsNullOrWhiteSpace(editName)) return;

        var entity = new CredentialSchema
        {
            Id = editingId ?? 0,
            Name = editName.Trim(),
            Description = string.IsNullOrWhiteSpace(editDescription) ? null : editDescription.Trim(),
            TypeUri = string.IsNullOrWhiteSpace(editTypeUri) ? null : editTypeUri.Trim(),
            Format = editFormat,
            DefaultValidityDays = editValidityDays,
            ClaimsSchemaJson = editClaimsSchemaJson,
            IsPreset = editingIsPreset,
        };

        try
        {
            await SchemaService.SaveAsync(entity);
            ToastService.ShowSuccess($"Schema '{entity.Name}' saved.");
            saveError = string.Empty;
            dialogHidden = true;
            await LoadAsync();
        }
        catch (Exception ex)
        {
            saveError = ex.Message;
        }
    }

    private async Task DeleteAsync(CredentialSchema s)
    {
        if (s.IsPreset) return;

        var impacts = await SchemaService.GetDeletionImpactAsync(s.Id);
        var message = impacts.Count > 0
            ? $"Delete schema '{s.Name}'? {string.Join("; ", impacts.Select(i => $"{i.Count} {i.Label}"))}"
            : $"Delete schema '{s.Name}'?";

        var dialog = await DialogService.ShowConfirmationAsync(message, "Delete", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            try
            {
                await SchemaService.DeleteAsync(s.Id);
                ToastService.ShowSuccess($"Schema '{s.Name}' deleted.");
                await LoadAsync();
            }
            catch (Exception ex)
            {
                ToastService.ShowError($"Delete failed: {ex.Message}");
            }
        }
    }
}

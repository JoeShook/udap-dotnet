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
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.Common.Data;
using Sigil.Vc.Services;
using Sigil.Vc.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class Credentials
{
    [Inject] private CredentialIssuanceService IssuanceService { get; set; } = null!;
    [Inject] private CredentialSchemaService SchemaService { get; set; } = null!;
    [Inject] private CredentialVerifier Verifier { get; set; } = null!;
    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    private List<IssuedCredentialViewModel> credentials = new();
    private List<TrustDomainOption> trustDomainOptions = new();
    private List<SchemaOption> schemaOptions = new();
    private List<DidOption> issuerOptions = new();

    private bool issueDialogHidden = true;
    private bool detailDialogHidden = true;

    private TrustDomainOption? selectedTrustDomain;
    private SchemaOption? selectedSchema;
    private DidOption? selectedIssuer;
    private string subjectDid = string.Empty;
    private string claimsJson = "{\n  \"name\": \"\",\n  \"role\": \"\"\n}";
    private string issueError = string.Empty;
    private CredentialIssuanceResult? lastIssueResult;

    private IssuedCredentialViewModel? selectedDetail;
    private CredentialVerifyResult? verifyResult;

    protected override async Task OnInitializedAsync()
    {
        await LoadAsync();
        await LoadOptionsAsync();
    }

    private async Task LoadAsync() => credentials = await IssuanceService.GetAllAsync();

    private async Task LoadOptionsAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        trustDomainOptions = await db.TrustDomains
            .OrderBy(td => td.Name)
            .Select(td => new TrustDomainOption(td.Id, td.Name))
            .ToListAsync();

        var schemas = await SchemaService.GetAllAsync();
        schemaOptions = schemas
            .Select(s => new SchemaOption(s.Id, $"{s.Name} ({s.Format})"))
            .ToList();

        issuerOptions = await db.DidDocuments
            .Where(d => !d.Deactivated)
            .OrderByDescending(d => d.CreatedAt)
            .Select(d => new DidOption(d.Id, d.Did))
            .ToListAsync();
    }

    private bool CanIssue() =>
        selectedTrustDomain != null &&
        selectedSchema != null &&
        selectedIssuer != null &&
        !string.IsNullOrWhiteSpace(subjectDid) &&
        !string.IsNullOrWhiteSpace(claimsJson);

    private void ShowIssueDialog()
    {
        selectedTrustDomain = trustDomainOptions.FirstOrDefault();
        selectedSchema = schemaOptions.FirstOrDefault();
        selectedIssuer = issuerOptions.FirstOrDefault();
        subjectDid = string.Empty;
        claimsJson = "{\n  \"name\": \"\",\n  \"role\": \"\"\n}";
        issueError = string.Empty;
        lastIssueResult = null;
        issueDialogHidden = false;
    }

    private async Task IssueAsync()
    {
        if (!CanIssue() || selectedTrustDomain == null || selectedSchema == null || selectedIssuer == null) return;

        try
        {
            lastIssueResult = await IssuanceService.IssueAsync(new CredentialIssuanceRequest(
                TrustDomainId: selectedTrustDomain.Id,
                CredentialSchemaId: selectedSchema.Id,
                IssuerDidDocumentId: selectedIssuer.Id,
                SubjectDid: subjectDid.Trim(),
                ClaimsJson: claimsJson));

            issueError = string.Empty;
            ToastService.ShowSuccess($"Issued credential {lastIssueResult.CredentialId}");
            await LoadAsync();
        }
        catch (Exception ex)
        {
            issueError = ex.Message;
        }
    }

    private void ShowDetail(IssuedCredentialViewModel c)
    {
        selectedDetail = c;
        verifyResult = null;
        detailDialogHidden = false;
    }

    private async Task VerifyAsync()
    {
        if (selectedDetail == null) return;
        verifyResult = await Verifier.VerifyAsync(selectedDetail.SignedCredential);
    }

    private async Task RevokeAsync(IssuedCredentialViewModel c)
    {
        var dialog = await DialogService.ShowConfirmationAsync(
            $"Revoke credential {c.CredentialId}? Verifiers checking status will reject it.",
            "Revoke", "Cancel", "Confirm Revoke");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            await IssuanceService.RevokeAsync(c.Id);
            ToastService.ShowSuccess($"Revoked {c.CredentialId}");
            await LoadAsync();
        }
    }

    private record TrustDomainOption(int Id, string Name);
    private record SchemaOption(int Id, string Label);
    private record DidOption(int Id, string Label);
}

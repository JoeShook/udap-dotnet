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
using Sigil.Did.Services;
using Sigil.Did.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class Dids
{
    [Inject] private DidIssuanceService IssuanceService { get; set; } = null!;
    [Inject] private DidTemplateService TemplateService { get; set; } = null!;
    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    private List<DidDocumentViewModel> dids = new();
    private List<TrustDomainOption> trustDomainOptions = new();
    private List<DidTemplateOption> didTemplateOptions = new();

    private bool mintDialogHidden = true;
    private bool detailDialogHidden = true;

    private TrustDomainOption? selectedTrustDomain;
    private DidTemplateOption? selectedDidTemplate;
    private string mintError = string.Empty;
    private DidIssuanceResult? lastMintResult;

    private DidDocumentViewModel? selectedDetail;

    protected override async Task OnInitializedAsync()
    {
        await LoadAsync();
        await LoadOptionsAsync();
    }

    private async Task LoadAsync() => dids = await IssuanceService.GetAllAsync();

    private async Task LoadOptionsAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();
        trustDomainOptions = await db.TrustDomains
            .OrderBy(td => td.Name)
            .Select(td => new TrustDomainOption(td.Id, td.Name))
            .ToListAsync();

        var templates = await TemplateService.GetAllAsync();
        didTemplateOptions = templates
            .Select(t => new DidTemplateOption(t.Id, $"{t.Name} ({t.Method}, {t.KeyAlgorithm})"))
            .ToList();
    }

    private void ShowMintDialog()
    {
        selectedTrustDomain = trustDomainOptions.FirstOrDefault();
        selectedDidTemplate = didTemplateOptions.FirstOrDefault();
        mintError = string.Empty;
        lastMintResult = null;
        mintDialogHidden = false;
    }

    private async Task MintAsync()
    {
        if (selectedTrustDomain == null || selectedDidTemplate == null) return;

        try
        {
            lastMintResult = await IssuanceService.IssueDidAsync(new DidIssuanceRequest(
                TrustDomainId: selectedTrustDomain.Id,
                DidTemplateId: selectedDidTemplate.Id));
            mintError = string.Empty;
            ToastService.ShowSuccess($"Minted {lastMintResult.Did}");
            await LoadAsync();
        }
        catch (Exception ex)
        {
            mintError = ex.Message;
        }
    }

    private void ShowDetail(DidDocumentViewModel vm)
    {
        selectedDetail = vm;
        detailDialogHidden = false;
    }

    private async Task DeactivateAsync(DidDocumentViewModel vm)
    {
        var dialog = await DialogService.ShowConfirmationAsync(
            $"Deactivate DID '{vm.Did}'? Issued credentials will fail verification.",
            "Deactivate", "Cancel", "Confirm Deactivate");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            await IssuanceService.DeactivateAsync(vm.Id);
            ToastService.ShowSuccess($"Deactivated {vm.Did}");
            await LoadAsync();
        }
    }

    private record TrustDomainOption(int Id, string Name);
    private record DidTemplateOption(int Id, string Label);
}

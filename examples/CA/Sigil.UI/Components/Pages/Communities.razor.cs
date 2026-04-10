using Microsoft.AspNetCore.Components;
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.Common.Data;
using Sigil.Common.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class Communities
{
    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;

    private List<CommunityViewModel> communities = new();
    private bool addDialogHidden = true;
    private string newCommunityName = string.Empty;
    private string newCommunityDescription = string.Empty;

    protected override async Task OnInitializedAsync()
    {
        await LoadCommunitiesAsync();
    }

    private async Task LoadCommunitiesAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();

        communities = await db.Communities
            .Select(c => new CommunityViewModel
            {
                Id = c.Id,
                Name = c.Name,
                Description = c.Description,
                Enabled = c.Enabled,
                CreatedAt = c.CreatedAt,
                RootCaCount = c.CaCertificates.Count(ca => ca.ParentId == null),
                TotalCertCount = c.CaCertificates.Count()
                    + c.CaCertificates.SelectMany(ca => ca.IssuedCertificates).Count()
            })
            .OrderBy(c => c.Name)
            .ToListAsync();
    }

    private void ShowAddDialog()
    {
        newCommunityName = string.Empty;
        newCommunityDescription = string.Empty;
        addDialogHidden = false;
    }

    private async Task AddCommunityAsync()
    {
        if (string.IsNullOrWhiteSpace(newCommunityName)) return;

        await using var db = await DbFactory.CreateDbContextAsync();

        db.Communities.Add(new Sigil.Common.Data.Entities.Community
        {
            Name = newCommunityName.Trim(),
            Description = string.IsNullOrWhiteSpace(newCommunityDescription) ? null : newCommunityDescription.Trim(),
            Enabled = true
        });

        await db.SaveChangesAsync();
        addDialogHidden = true;
        await LoadCommunitiesAsync();
    }

    private async Task DeleteCommunityAsync(CommunityViewModel community)
    {
        var dialog = await DialogService.ShowConfirmationAsync(
            $"Delete community '{community.Name}' and all its certificates?",
            "Delete", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            var entity = await db.Communities.FindAsync(community.Id);
            if (entity != null)
            {
                db.Communities.Remove(entity);
                await db.SaveChangesAsync();
            }

            await LoadCommunitiesAsync();
        }
    }

    private void NavigateToExplorer(int communityId)
    {
        Navigation.NavigateTo($"/explorer/{communityId}");
    }
}

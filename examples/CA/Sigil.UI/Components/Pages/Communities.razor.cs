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
using Sigil.Common.Services;
using Sigil.Common.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class Communities
{
    [Inject] private CommunityService CommunityService { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;

    [SupplyParameterFromQuery] public string? Action { get; set; }
    [SupplyParameterFromQuery] public int? Edit { get; set; }

    private List<CommunityViewModel> communities = new();
    private bool addDialogHidden = true;
    private string newCommunityName = string.Empty;
    private string newCommunityDescription = string.Empty;
    private int newCommunityExpiry = 7;
    private List<BaseUrlEntry> newCommunityBaseUrls = new();

    // Edit dialog
    private bool editDialogHidden = true;
    private int editCommunityId;
    private string editCommunityName = string.Empty;
    private string editCommunityDescription = string.Empty;
    private int editCommunityExpiry = 7;
    private List<BaseUrlEntry> editCommunityBaseUrls = new();

    // Folder browser
    private bool folderBrowserHidden = true;
    private string appBasePath = Directory.GetCurrentDirectory();
    private string folderBrowserCurrentPath = string.Empty;
    private string? folderBrowserSelectedSubdir;
    private List<string> folderBrowserSubdirectories = new();
    private bool folderBrowserUseRelative = true;
    private BaseUrlEntry? folderBrowserTarget;

    private string folderBrowserDisplayPath
    {
        get
        {
            var selected = folderBrowserSelectedSubdir ?? folderBrowserCurrentPath;
            if (string.IsNullOrEmpty(selected)) return string.Empty;
            if (folderBrowserUseRelative)
                return Path.GetRelativePath(appBasePath, selected);
            return selected;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        await LoadCommunitiesAsync();
        if (Action == "new")
        {
            ShowAddDialog();
        }
        else if (Edit.HasValue)
        {
            var target = communities.FirstOrDefault(c => c.Id == Edit.Value);
            if (target != null)
                ShowEditDialog(target);
        }
    }

    private async Task LoadCommunitiesAsync()
    {
        communities = await CommunityService.GetAllAsync();
    }

    private void ShowAddDialog()
    {
        newCommunityName = string.Empty;
        newCommunityDescription = string.Empty;
        newCommunityExpiry = 7;
        newCommunityBaseUrls = new List<BaseUrlEntry>();
        addDialogHidden = false;
    }

    private async Task AddCommunityAsync()
    {
        if (string.IsNullOrWhiteSpace(newCommunityName)) return;

        var baseUrls = newCommunityBaseUrls
            .Where(e => !string.IsNullOrWhiteSpace(e.Value))
            .Select(e => (e.Value, (string?)e.PublishingBasePath))
            .ToList();

        await CommunityService.CreateAsync(newCommunityName, newCommunityDescription, baseUrls, newCommunityExpiry);
        addDialogHidden = true;
        await LoadCommunitiesAsync();
    }

    // Impact confirmation dialog state
    private bool impactDialogHidden = true;
    private string impactDialogTitle = "Confirm";
    private string impactDialogMessage = string.Empty;
    private string impactDialogConfirmLabel = "Confirm";
    private List<ImpactItem>? impactDialogImpacts;
    private Func<Task>? impactDialogOnConfirm;
    private bool impactDialogBusy;

    private async Task DeleteCommunityAsync(CommunityViewModel community)
    {
        var impacts = await CommunityService.GetDeletionImpactAsync(community.Id);
        impactDialogTitle = $"Delete community '{community.Name}'?";
        impactDialogMessage = "All certificates, CRLs, and revocation records in this community will be permanently deleted. This cannot be undone.";
        impactDialogConfirmLabel = "Delete Community";
        impactDialogImpacts = impacts;
        impactDialogOnConfirm = () => ConfirmDeleteCommunityAsync(community.Id);
        impactDialogBusy = false;
        impactDialogHidden = false;
    }

    private async Task ConfirmDeleteCommunityAsync(int communityId)
    {
        await CommunityService.DeleteAsync(communityId);
        await LoadCommunitiesAsync();
    }

    private async Task OnImpactDialogConfirmAsync()
    {
        if (impactDialogOnConfirm == null) return;
        impactDialogBusy = true;
        StateHasChanged();
        try
        {
            await impactDialogOnConfirm();
        }
        finally
        {
            impactDialogHidden = true;
            impactDialogBusy = false;
        }
    }

    private void OnImpactDialogCancel() => impactDialogHidden = true;

    private void ShowEditDialog(CommunityViewModel community)
    {
        editCommunityId = community.Id;
        editCommunityName = community.Name;
        editCommunityDescription = community.Description ?? string.Empty;
        editCommunityExpiry = community.CrlValidityDays;
        editCommunityBaseUrls = community.BaseUrls
            .Select(u => new BaseUrlEntry { Value = u.Url, PublishingBasePath = u.PublishingBasePath ?? string.Empty })
            .ToList();
        editDialogHidden = false;
    }

    private async Task SaveEditAsync()
    {
        if (string.IsNullOrWhiteSpace(editCommunityName)) return;

        var baseUrls = editCommunityBaseUrls
            .Where(e => !string.IsNullOrWhiteSpace(e.Value))
            .Select(e => (e.Value, (string?)e.PublishingBasePath))
            .ToList();

        await CommunityService.UpdateAsync(editCommunityId, editCommunityName, editCommunityDescription, baseUrls, editCommunityExpiry);

        editDialogHidden = true;
        await LoadCommunitiesAsync();
    }

    private void NavigateToExplorer(int communityId)
    {
        Navigation.NavigateTo($"/explorer/{communityId}");
    }

    // --- Folder Browser ---

    private void ShowFolderBrowser(BaseUrlEntry target)
    {
        folderBrowserTarget = target;
        folderBrowserUseRelative = true;

        if (!string.IsNullOrWhiteSpace(target.PublishingBasePath))
        {
            var resolved = Path.IsPathRooted(target.PublishingBasePath)
                ? target.PublishingBasePath
                : Path.GetFullPath(Path.Combine(appBasePath, target.PublishingBasePath));
            folderBrowserCurrentPath = Directory.Exists(resolved) ? resolved : appBasePath;
        }
        else
        {
            folderBrowserCurrentPath = appBasePath;
        }

        folderBrowserSelectedSubdir = null;
        LoadSubdirectories();
        folderBrowserHidden = false;
    }

    private void LoadSubdirectories()
    {
        try
        {
            folderBrowserSubdirectories = Directory.GetDirectories(folderBrowserCurrentPath)
                .OrderBy(d => Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            folderBrowserSubdirectories = new();
        }
    }

    private void FolderBrowserNavigateUp()
    {
        var parent = Directory.GetParent(folderBrowserCurrentPath);
        if (parent != null)
        {
            folderBrowserCurrentPath = parent.FullName;
            folderBrowserSelectedSubdir = null;
            LoadSubdirectories();
        }
    }

    private void FolderBrowserSelectDir(string dir)
    {
        folderBrowserSelectedSubdir = dir;
    }

    private void FolderBrowserNavigateInto(string dir)
    {
        folderBrowserCurrentPath = dir;
        folderBrowserSelectedSubdir = null;
        LoadSubdirectories();
    }

    private void FolderBrowserConfirm()
    {
        if (folderBrowserTarget == null) return;

        var selected = folderBrowserSelectedSubdir ?? folderBrowserCurrentPath;
        folderBrowserTarget.PublishingBasePath = folderBrowserUseRelative
            ? Path.GetRelativePath(appBasePath, selected)
            : selected;

        folderBrowserHidden = true;
    }

    private class BaseUrlEntry
    {
        public string Value { get; set; } = string.Empty;
        public string PublishingBasePath { get; set; } = string.Empty;
    }
}

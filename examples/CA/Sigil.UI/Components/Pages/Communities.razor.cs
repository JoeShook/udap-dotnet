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
using Sigil.Common.Data.Entities;
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
    private List<BaseUrlEntry> newCommunityBaseUrls = new();

    // Edit dialog
    private bool editDialogHidden = true;
    private int editCommunityId;
    private string editCommunityName = string.Empty;
    private string editCommunityDescription = string.Empty;
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
                BaseUrls = c.BaseUrls.OrderBy(bu => bu.SortOrder)
                    .Select(bu => new BaseUrlViewModel { Url = bu.Url, PublishingBasePath = bu.PublishingBasePath })
                    .ToList(),
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
        newCommunityBaseUrls = new List<BaseUrlEntry>();
        addDialogHidden = false;
    }

    private async Task AddCommunityAsync()
    {
        if (string.IsNullOrWhiteSpace(newCommunityName)) return;

        await using var db = await DbFactory.CreateDbContextAsync();

        var community = new Community
        {
            Name = newCommunityName.Trim(),
            Description = string.IsNullOrWhiteSpace(newCommunityDescription) ? null : newCommunityDescription.Trim(),
            Enabled = true
        };

        var sortOrder = 0;
        foreach (var entry in newCommunityBaseUrls)
        {
            if (!string.IsNullOrWhiteSpace(entry.Value))
            {
                community.BaseUrls.Add(new CommunityBaseUrl
                {
                    Url = entry.Value.Trim().TrimEnd('/'),
                    SortOrder = sortOrder++,
                    PublishingBasePath = string.IsNullOrWhiteSpace(entry.PublishingBasePath) ? null : entry.PublishingBasePath.Trim()
                });
            }
        }

        db.Communities.Add(community);
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

    private void ShowEditDialog(CommunityViewModel community)
    {
        editCommunityId = community.Id;
        editCommunityName = community.Name;
        editCommunityDescription = community.Description ?? string.Empty;
        editCommunityBaseUrls = community.BaseUrls
            .Select(u => new BaseUrlEntry { Value = u.Url, PublishingBasePath = u.PublishingBasePath ?? string.Empty })
            .ToList();
        editDialogHidden = false;
    }

    private async Task SaveEditAsync()
    {
        if (string.IsNullOrWhiteSpace(editCommunityName)) return;

        await using var db = await DbFactory.CreateDbContextAsync();
        var entity = await db.Communities
            .Include(c => c.BaseUrls)
            .FirstOrDefaultAsync(c => c.Id == editCommunityId);

        if (entity != null)
        {
            entity.Name = editCommunityName.Trim();
            entity.Description = string.IsNullOrWhiteSpace(editCommunityDescription) ? null : editCommunityDescription.Trim();

            entity.BaseUrls.Clear();
            var sortOrder = 0;
            foreach (var entry in editCommunityBaseUrls)
            {
                if (!string.IsNullOrWhiteSpace(entry.Value))
                {
                    entity.BaseUrls.Add(new CommunityBaseUrl
                    {
                        Url = entry.Value.Trim().TrimEnd('/'),
                        SortOrder = sortOrder++,
                        PublishingBasePath = string.IsNullOrWhiteSpace(entry.PublishingBasePath) ? null : entry.PublishingBasePath.Trim()
                    });
                }
            }

            await db.SaveChangesAsync();
        }

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

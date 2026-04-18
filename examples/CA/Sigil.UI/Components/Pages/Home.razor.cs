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
using Sigil.Common.Data;

namespace Sigil.UI.Components.Pages;

public partial class Home
{
    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;

    private bool isLoading = true;

    // Summary stats
    private int communityCount;
    private int caCertCount;
    private int issuedCertCount;
    private int templateCount;

    // Community summaries
    private List<CommunitySummary> communitySummaries = new();

    // Expiring / expired certs
    private List<CertRow> expiringCerts = new();
    private List<CertRow> expiredCerts = new();

    // Overdue CRLs
    private List<CrlRow> overdueCrls = new();

    // Revoked certs
    private int revokedCertCount;

    protected override async Task OnInitializedAsync()
    {
        await LoadDashboardAsync();
    }

    private async Task LoadDashboardAsync()
    {
        isLoading = true;
        StateHasChanged();

        await using var db = await DbFactory.CreateDbContextAsync();
        var now = DateTime.UtcNow;
        var expiringSoonThreshold = now.AddDays(60);

        // Counts
        communityCount = await db.Communities.CountAsync();
        caCertCount = await db.CaCertificates.CountAsync();
        issuedCertCount = await db.IssuedCertificates.CountAsync();
        templateCount = await db.CertificateTemplates.CountAsync();

        // Community summaries
        communitySummaries = await db.Communities
            .Select(c => new CommunitySummary
            {
                Id = c.Id,
                Name = c.Name,
                CaCount = c.CaCertificates.Count,
                IssuedCount = c.CaCertificates.SelectMany(ca => ca.IssuedCertificates).Count(),
                ExpiredCaCount = c.CaCertificates.Count(ca => ca.NotAfter <= now),
                ExpiredIssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => i.NotAfter <= now),
                ExpiringCaCount = c.CaCertificates
                    .Count(ca => ca.NotAfter > now && ca.NotAfter <= expiringSoonThreshold),
                ExpiringIssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => i.NotAfter > now && i.NotAfter <= expiringSoonThreshold),
                OverdueCrlCount = c.CaCertificates
                    .SelectMany(ca => ca.Crls)
                    .Count(crl => crl.NextUpdate < now),
            })
            .OrderBy(c => c.Name)
            .ToListAsync();

        // Expiring certs (within 60 days, not yet expired)
        var expiringCas = await db.CaCertificates
            .Where(c => c.NotAfter > now && c.NotAfter <= expiringSoonThreshold && !c.IsArchived)
            .Select(c => new CertRow
            {
                Name = c.Name,
                Subject = c.Subject,
                Thumbprint = c.Thumbprint,
                NotAfter = c.NotAfter,
                CommunityName = c.Community.Name,
                CommunityId = c.CommunityId,
                CertType = "CA",
                DaysRemaining = (int)(c.NotAfter - now).TotalDays
            })
            .ToListAsync();

        var expiringIssued = await db.IssuedCertificates
            .Where(i => i.NotAfter > now && i.NotAfter <= expiringSoonThreshold && !i.IsRevoked && !i.IsArchived)
            .Select(i => new CertRow
            {
                Name = i.Name,
                Subject = i.Subject,
                Thumbprint = i.Thumbprint,
                NotAfter = i.NotAfter,
                CommunityName = i.IssuingCaCertificate.Community.Name,
                CommunityId = i.IssuingCaCertificate.CommunityId,
                CertType = "End Entity",
                DaysRemaining = (int)(i.NotAfter - now).TotalDays
            })
            .ToListAsync();

        expiringCerts = expiringCas.Concat(expiringIssued)
            .OrderBy(c => c.NotAfter)
            .ToList();

        // Expired certs (most recent 20)
        var expiredCas = await db.CaCertificates
            .Where(c => c.NotAfter <= now && !c.IsArchived)
            .Select(c => new CertRow
            {
                Name = c.Name,
                Subject = c.Subject,
                Thumbprint = c.Thumbprint,
                NotAfter = c.NotAfter,
                CommunityName = c.Community.Name,
                CommunityId = c.CommunityId,
                CertType = "CA",
                DaysRemaining = (int)(c.NotAfter - now).TotalDays
            })
            .ToListAsync();

        var expiredIssued = await db.IssuedCertificates
            .Where(i => i.NotAfter <= now && !i.IsRevoked && !i.IsArchived)
            .Select(i => new CertRow
            {
                Name = i.Name,
                Subject = i.Subject,
                Thumbprint = i.Thumbprint,
                NotAfter = i.NotAfter,
                CommunityName = i.IssuingCaCertificate.Community.Name,
                CommunityId = i.IssuingCaCertificate.CommunityId,
                CertType = "End Entity",
                DaysRemaining = (int)(i.NotAfter - now).TotalDays
            })
            .ToListAsync();

        expiredCerts = expiredCas.Concat(expiredIssued)
            .OrderByDescending(c => c.NotAfter)
            .Take(20)
            .ToList();

        // Overdue CRLs
        overdueCrls = await db.Crls
            .Where(c => c.NextUpdate < now && !c.IsArchived)
            .Select(c => new CrlRow
            {
                CrlNumber = c.CrlNumber,
                CaName = c.CaCertificate.Name,
                CaThumbprint = c.CaCertificate.Thumbprint,
                CommunityName = c.CaCertificate.Community.Name,
                CommunityId = c.CaCertificate.CommunityId,
                NextUpdate = c.NextUpdate,
                DaysOverdue = (int)(now - c.NextUpdate).TotalDays
            })
            .OrderByDescending(c => c.DaysOverdue)
            .ToListAsync();

        // Revoked count
        revokedCertCount = await db.IssuedCertificates.CountAsync(i => i.IsRevoked);

        isLoading = false;
        StateHasChanged();
    }

    private void NavigateToCommunity(int communityId)
    {
        Navigation.NavigateTo($"/explorer/{communityId}");
    }

    private void NavigateToCert(int communityId, string thumbprint)
    {
        Navigation.NavigateTo($"/explorer/{communityId}?thumbprint={thumbprint}");
    }

    // --- View Models ---

    private class CommunitySummary
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public int CaCount { get; set; }
        public int IssuedCount { get; set; }
        public int ExpiredCaCount { get; set; }
        public int ExpiredIssuedCount { get; set; }
        public int ExpiringCaCount { get; set; }
        public int ExpiringIssuedCount { get; set; }
        public int OverdueCrlCount { get; set; }
        public int TotalCerts => CaCount + IssuedCount;
        public int TotalExpired => ExpiredCaCount + ExpiredIssuedCount;
        public int TotalExpiring => ExpiringCaCount + ExpiringIssuedCount;
        public bool IsHealthy => TotalExpired == 0 && TotalExpiring == 0 && OverdueCrlCount == 0;
    }

    private class CertRow
    {
        public string Name { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public DateTime NotAfter { get; set; }
        public string CommunityName { get; set; } = string.Empty;
        public int CommunityId { get; set; }
        public string CertType { get; set; } = string.Empty;
        public int DaysRemaining { get; set; }
    }

    private class CrlRow
    {
        public long CrlNumber { get; set; }
        public string CaName { get; set; } = string.Empty;
        public string CaThumbprint { get; set; } = string.Empty;
        public string CommunityName { get; set; } = string.Empty;
        public int CommunityId { get; set; }
        public DateTime NextUpdate { get; set; }
        public int DaysOverdue { get; set; }
    }
}

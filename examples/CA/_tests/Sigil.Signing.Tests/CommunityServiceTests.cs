#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Common.Data;
using Sigil.Common.Services;

namespace Sigil.Signing.Tests;

public class CommunityServiceTests
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory = new TestDbContextFactory();

    private CommunityService CreateService() =>
        new(_dbFactory, NullLogger<CommunityService>.Instance);

    [Fact]
    public async Task GetAll_EmptyDb_ReturnsEmpty()
    {
        var service = CreateService();

        var result = await service.GetAllAsync();

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task CreateAsync_BasicCommunity_Persists()
    {
        var service = CreateService();

        var community = await service.CreateAsync("My Community", "A test community", []);

        community.Id.Should().BeGreaterThan(0);
        community.Name.Should().Be("My Community");

        var all = await service.GetAllAsync();
        all.Should().ContainSingle();
        all[0].Name.Should().Be("My Community");
        all[0].Description.Should().Be("A test community");
    }

    [Fact]
    public async Task CreateAsync_WithBaseUrls_PersistsUrls()
    {
        var service = CreateService();

        var urls = new List<(string Url, string? PublishingBasePath)>
        {
            ("https://example.com/fhir", "/publish/path"),
            ("https://other.com/fhir", null)
        };

        await service.CreateAsync("URL Community", null, urls);

        var all = await service.GetAllAsync();
        all.Should().ContainSingle();
        all[0].BaseUrls.Should().HaveCount(2);
        all[0].BaseUrls[0].Url.Should().Be("https://example.com/fhir");
        all[0].BaseUrls[0].PublishingBasePath.Should().Be("/publish/path");
        all[0].BaseUrls[1].Url.Should().Be("https://other.com/fhir");
    }

    [Fact]
    public async Task CreateAsync_TrimsNameAndUrl()
    {
        var service = CreateService();

        await service.CreateAsync("  Spaced  ", null, [("  https://example.com/  ", null)]);

        var all = await service.GetAllAsync();
        all[0].Name.Should().Be("Spaced");
        all[0].BaseUrls[0].Url.Should().Be("https://example.com");
    }

    [Fact]
    public async Task UpdateAsync_ChangesNameAndUrls()
    {
        var service = CreateService();
        var community = await service.CreateAsync("Original", null, [("https://old.com", null)]);

        await service.UpdateAsync(community.Id, "Renamed", "New desc",
            [("https://new.com", "/new/path")]);

        var all = await service.GetAllAsync();
        all.Should().ContainSingle();
        all[0].Name.Should().Be("Renamed");
        all[0].Description.Should().Be("New desc");
        all[0].BaseUrls.Should().ContainSingle();
        all[0].BaseUrls[0].Url.Should().Be("https://new.com");
    }

    [Fact]
    public async Task DeleteAsync_RemovesCommunity()
    {
        var service = CreateService();
        var community = await service.CreateAsync("To Delete", null, []);

        await service.DeleteAsync(community.Id);

        var all = await service.GetAllAsync();
        all.Should().BeEmpty();
    }

    [Fact]
    public async Task DeleteAsync_NonexistentId_DoesNotThrow()
    {
        var service = CreateService();

        var act = () => service.DeleteAsync(99999);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task GetAll_OrdersByName()
    {
        var service = CreateService();
        await service.CreateAsync("Zebra", null, []);
        await service.CreateAsync("Alpha", null, []);
        await service.CreateAsync("Middle", null, []);

        var all = await service.GetAllAsync();

        all.Should().HaveCount(3);
        all[0].Name.Should().Be("Alpha");
        all[1].Name.Should().Be("Middle");
        all[2].Name.Should().Be("Zebra");
    }
}

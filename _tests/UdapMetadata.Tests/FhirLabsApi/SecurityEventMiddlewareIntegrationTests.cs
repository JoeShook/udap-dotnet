#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;
using fhirLabsProgram = FhirLabsApi.Program;

namespace UdapMetadata.Tests.FhirLabsApi;

public class SecurityEventTestFixture : WebApplicationFactory<fhirLabsProgram>
{
    public ITestOutputHelper? Output { get; set; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("contentRoot", ApiTestFixture.ProgramPath);
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddXUnit(Output!);
        });

        return base.CreateHost(builder);
    }
}

public class SecurityEventMiddlewareIntegrationTests : IClassFixture<SecurityEventTestFixture>
{
    private readonly SecurityEventTestFixture _fixture;

    public SecurityEventMiddlewareIntegrationTests(SecurityEventTestFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _fixture.Output = output;
    }

    [Fact]
    public async Task Request_WithNoAuthHeader_Returns401()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync("/fhir/r4/Patient");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Request_WithInvalidToken_Returns401()
    {
        var client = _fixture.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "not-a-valid-jwt");

        var response = await client.GetAsync("/fhir/r4/Patient");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Request_WithExpiredToken_Returns401()
    {
        var token = CreateTestJwt("expired-client", expired: true);
        var client = _fixture.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/fhir/r4/Patient");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Request_WithBearerSchemeOnly_Returns401()
    {
        var client = _fixture.CreateClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer");

        var response = await client.GetAsync("/fhir/r4/Patient");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Request_WithValidTokenButWrongSigningKey_Returns401()
    {
        var token = CreateTestJwt("wrong-key-client");
        var client = _fixture.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/fhir/r4/Patient");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task MetadataEndpoint_AllowsAnonymous_Returns200()
    {
        var client = _fixture.CreateClient();

        var response = await client.GetAsync("/fhir/r4/.well-known/udap");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private static string CreateTestJwt(string clientId, bool expired = false)
    {
        var key = new SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes("this-is-a-test-key-that-is-long-enough-for-hmac"));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new("sub", "test-subject"),
            new("client_id", clientId)
        };

        var token = new JwtSecurityToken(
            issuer: "https://test-issuer.example.com",
            claims: claims,
            expires: expired ? DateTime.UtcNow.AddHours(-1) : DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

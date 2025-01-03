﻿#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

//
// The following test and pipeline technique are from the original Duende source code tests.
// I will be adapting these to test UDAP specific features where some of the tests are identical
// as I do want the resulting UDAP features to live in harmony with the existing Identity Server.
//

// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using FluentAssertions;
using IdentityModel;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Client.Client;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class UdapResponseTypeResponseModeTests
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly UdapAuthServerPipeline _mockPipeline = new UdapAuthServerPipeline();
    

    public UdapResponseTypeResponseModeTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        var sureFhirLabsAnchor  = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        _mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton(new ServerSettings
            {
                DefaultUserScopes = "user/*.read",
                DefaultSystemScopes = "system/*.read",
                ForceStateParamOnAuthorizationCode = true,
                RequireConsent = false,
                RequirePkce = false
            });

            s.AddSingleton(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });

        };

        _mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // TODO: PR Deunde for this issue.
            // They register Clients as IEnumerable<Client> in AddInMemoryClients extension
            s.AddSingleton(_mockPipeline.Clients);

            s.AddScoped<IUdapClient>(sp => new UdapClient(
                _mockPipeline.BackChannelClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        
        _mockPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors = [new Anchor(sureFhirLabsAnchor, "udap://fhirlabs.net")
            {
                BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                Name = sureFhirLabsAnchor.Subject,
                Enabled = true,
                Intermediates = new List<Intermediate>()
                {
                    new Intermediate(intermediateCert)
                    {
                        BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                        EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                        Name = intermediateCert.Subject,
                        Enabled = true
                    }
                }
            }]
        });

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());

        _mockPipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        _mockPipeline.ApiScopes.Add(new ApiScope("udap"));

        _mockPipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com"),
                new Claim("role", "Attorney")
            ]
        });
    }

    
    [Fact]
    public async Task Request_response_type_missing_results_in_unsupported_response_type()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();
        
        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

       
        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint, 
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "removeMe", // missing
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        url = url.Replace("response_type=removeMe", "");

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var query = response.Headers.Location?.Query;
        // _testOutputHelper.WriteLine(query);
        var responseParams = QueryHelpers.ParseQuery(query);
        responseParams["error"].Should().BeEquivalentTo("invalid_request");
        responseParams["error_description"].Should().BeEquivalentTo("Missing response_type");
        responseParams["scope"].Should().BeEquivalentTo("openid");
        responseParams["state"].Should().BeEquivalentTo(state);
        responseParams["nonce"].Should().BeEquivalentTo(nonce);
    }

    /// <summary>
    /// If client does not include the state during connect/authorize and
    /// <see cref="ServerSettings.ForceStateParamOnAuthorizationCode"/> is true
    /// authorize will redirect with error.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task Request_state_missing_results_in_unsupported_response_type()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        
        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;


        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            // state: state, //missing state
            nonce: nonce);
        _testOutputHelper.WriteLine(url);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var query = response.Headers.Location?.Query;
        _testOutputHelper.WriteLine(query);
        var responseParams = QueryHelpers.ParseQuery(query);
        responseParams["error"].Should().BeEquivalentTo("invalid_request");
        responseParams["error_description"].Should().BeEquivalentTo("Missing state");
        responseParams["response_type"].Should().BeEquivalentTo("code");
        responseParams["scope"].Should().BeEquivalentTo("openid");
        responseParams.Count(r => r.Key == "state").Should().Be(0);
        responseParams["nonce"].Should().BeEquivalentTo(nonce);
    }

    
    [Fact]
    public async Task Request_response_type_invalid_results_in_unsupported_response_type()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();
        
        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;


        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "invalid_response_type", // invalid
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var query = response.Headers.Location?.Query;
        // _testOutputHelper.WriteLine(query);
        var responseParams = QueryHelpers.ParseQuery(query);
        responseParams["error"].Should().BeEquivalentTo("invalid_request");
        responseParams["error_description"].Should().BeEquivalentTo("Response type not supported");
        responseParams["response_type"].Should().BeEquivalentTo("invalid_response_type");
        responseParams["scope"].Should().BeEquivalentTo("openid");
        responseParams["state"].Should().BeEquivalentTo(state);
        responseParams["nonce"].Should().BeEquivalentTo(nonce);
    }


    [Fact]
    public async Task Request_client_id_missing_results_in_invalid_request()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid system/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;


        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            // clientId: null,
            responseType: "code",
            // scope: "openid",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var errorMessage = await response.Content.ReadFromJsonAsync<ErrorMessage>();
        errorMessage.Should().NotBeNull();
        errorMessage!.Error.Should().Be("invalid_request"); //defined in Duende
        errorMessage.ErrorDescription.Should().BeEquivalentTo("Invalid client_id"); //defined in Duende
    }

    [Fact]
    public async Task Request_client_id_invalid_results_in_unauthorized_client()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();
        
        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: $"{resultDocument.ClientId!}_Invalid",
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var errorMessage = await response.Content.ReadFromJsonAsync<ErrorMessage>();
        errorMessage.Should().NotBeNull();
        errorMessage!.Error.Should().Be("unauthorized_client");
        errorMessage.ErrorDescription.Should().BeEquivalentTo("Unknown client or client not enabled");
    }


    [Fact]
    public async Task AuthorizeWithoutPKCSE_accepted()
    {

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> {"code"})
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .WithGrantType( "refresh_token" )
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );
       
        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        // Register
        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var clientId = resultDocument.ClientId;
        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        await _mockPipeline.LoginAsync("bob");

        // Authorize
        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid offline_access",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain("https://code_client/callback");
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        queryParams.Single(q => q.Key == "scope").Value.Should().BeEquivalentTo("openid offline_access");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(state);


        // Request Token From Auth Code
        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                clientId,
                "https://server/connect/token",
                clientCert,
                "https://code_client/callback",
                queryParams.First(p => p.Key == "code").Value)
        .Build();

        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        var tokenResponse = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);

        tokenResponse.Should().NotBeNull();
        tokenResponse.IdentityToken.Should().NotBeNull();
        var jwt = new JwtSecurityToken(tokenResponse.IdentityToken);
        new JwtSecurityToken(tokenResponse.AccessToken).Should().NotBeNull();

        using var jsonDocument = JsonDocument.Parse(jwt.Payload.SerializeToJson());
        var formattedStatement = JsonSerializer.Serialize(
            jsonDocument,
            IndentedJsonOptions
        );

        var formattedHeader = Base64UrlEncoder.Decode(jwt.EncodedHeader);

        _testOutputHelper.WriteLine(formattedHeader);
        _testOutputHelper.WriteLine(formattedStatement);


        // udap.org Tiered 4.3
        // aud: client_id of Resource Holder (matches client_id in Resource Holder request in Step 3.4)
        jwt.Claims.Should().Contain(c => c.Type == "aud");
        jwt.Claims.Single(c => c.Type == "aud").Value.Should().Be(clientId);

        // iss: Auth Servers unique identifying URI 
        jwt.Claims.Should().Contain(c => c.Type == "iss");
        jwt.Claims.Single(c => c.Type == "iss").Value.Should().Be(UdapAuthServerPipeline.BaseUrl);
        
    }

    [Fact]
    public async Task Request_accepted_RegisterWithDifferentRedirectUrl()
    {
        string httpsCodeClientCallback = "https://code_client/callback";
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var document = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { httpsCodeClientCallback })
            .Build();


        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(clientCert, document)
            .Build();

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: httpsCodeClientCallback,
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain(httpsCodeClientCallback);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        queryParams.Single(q => q.Key == "scope").Value.Should().BeEquivalentTo("openid");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(state);
        //iss ???


        //
        // Re-Register with different redirect url
        //

        httpsCodeClientCallback = "https://code_client/different_callback";
        document.RedirectUris = new List<string> { httpsCodeClientCallback };
        document.JwtId = CryptoRandom.CreateUniqueId();

        signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        //
        // Get AccessToken again
        //
        state = Guid.NewGuid().ToString();
        nonce = Guid.NewGuid().ToString();

        url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: httpsCodeClientCallback,
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain(httpsCodeClientCallback);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        queryParams.Single(q => q.Key == "scope").Value.Should().BeEquivalentTo("openid");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(state);
        //iss ???
    }

    /// <summary>
    /// Found a bug when testing with AEGIS
    /// Expect redirect_url requested to be persisted the same way as it was requested by the registering UDAP client.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task Request_accepted_URI_HostOnly()
    {
        var redirectUrl = "https://code_client";

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { redirectUrl })
            .BuildSoftwareStatement();
        
        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            Array.Empty<string>()
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;

        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var url = _mockPipeline.CreateAuthorizeUrl(
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: redirectUrl,
            state: state,
            nonce: nonce);

        _mockPipeline.BrowserClient.AllowAutoRedirect = false;
        response = await _mockPipeline.BrowserClient.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.AbsoluteUri.Should().Contain(redirectUrl);
        // _testOutputHelper.WriteLine(response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        queryParams.Should().Contain(p => p.Key == "code");
        queryParams.Single(q => q.Key == "scope").Value.Should().BeEquivalentTo("openid");
        queryParams.Single(q => q.Key == "state").Value.Should().BeEquivalentTo(state);
        //iss ???
    }


    [Fact]
    public async Task Request_invalid_redirect_url_results_in_invalid_request()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        await _mockPipeline.LoginAsync("bob");

        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid system/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();


        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue
        );

        _mockPipeline.BrowserClient.AllowAutoRedirect = true;


        var response = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var resultDocument = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        resultDocument.Should().NotBeNull();
        resultDocument!.ClientId.Should().NotBeNull();

        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();

        var udapClient = _mockPipeline.Resolve<IUdapClient>();

        response = await udapClient.Authorize(
            authorizationUrl: UdapAuthServerPipeline.AuthorizeEndpoint,
            clientId: resultDocument.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "http://www.udap.org/",
            state: state,
            nonce: nonce
        );


        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var errorMessage = await response.Content.ReadFromJsonAsync<ErrorMessage>();
        errorMessage.Should().NotBeNull();
        errorMessage!.Error.Should().Be("invalid_request"); //defined in Duende
        errorMessage.ErrorDescription.Should().BeEquivalentTo("Invalid redirect_uri"); //defined in Duende
    }
}

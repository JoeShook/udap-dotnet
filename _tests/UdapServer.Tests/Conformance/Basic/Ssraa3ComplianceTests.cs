#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityModel;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using UdapServer.Tests.Common;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// HL7 SSRAA 3.0.0 general requirements, "Normalization of URI values in JWTs": URI values in JWTs are
/// compared as exact, case-sensitive strings. Under <see cref="SsraaVersion.V2_0"/> and
/// <see cref="SsraaVersion.V3_0"/> the software statement <c>aud</c> and the client assertion <c>aud</c>
/// must equal the endpoint exactly; <see cref="SsraaVersion.V1_1"/> keeps the previous lenient comparison.
/// Also covers the authorization endpoint accepting POST as well as GET for the authorization code flow.
/// </summary>
[Collection("Udap.Auth.Server")]
public class Ssraa3ComplianceTests
{
    private const string ClientCertPath = "CertStore/issued/fhirlabs.net.client.pfx";

    [Fact]
    public void ServerSettings_Default_Is_V3_0()
    {
        var settings = new ServerSettings();

        Assert.Equal(SsraaVersion.V3_0, settings.SsraaVersion);
        Assert.True(settings.EffectiveRequirePkce);
        Assert.True(settings.EffectiveForceState);
        Assert.True(settings.EffectiveExactUriComparison);
    }

    [Theory]
    [InlineData(SsraaVersion.V1_1, false)]
    [InlineData(SsraaVersion.V2_0, true)]
    [InlineData(SsraaVersion.V3_0, true)]
    public void V3_0_Gets_At_Least_V2_0_Behaviour(SsraaVersion version, bool expected)
    {
        var settings = new ServerSettings { SsraaVersion = version };

        Assert.Equal(expected, settings.EffectiveRequirePkce);
        Assert.Equal(expected, settings.EffectiveForceState);
        Assert.Equal(expected, settings.EffectiveExactUriComparison);
    }

    [Theory]
    [InlineData(SsraaVersion.V2_0)]
    [InlineData(SsraaVersion.V3_0)]
    public async Task Registration_Exact_Aud_Succeeds(SsraaVersion version)
    {
        var pipeline = BuildPipeline(version);

        var response = await Register(pipeline, UdapAuthServerPipeline.RegistrationEndpoint);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Theory]
    [InlineData(SsraaVersion.V2_0, "https://SERVER/connect/register")]
    [InlineData(SsraaVersion.V2_0, "https://server:443/connect/register")]
    [InlineData(SsraaVersion.V2_0, "https://server/connect/register/")]
    [InlineData(SsraaVersion.V2_0, "https://server/Connect/Register")]
    [InlineData(SsraaVersion.V3_0, "https://SERVER/connect/register")]
    [InlineData(SsraaVersion.V3_0, "https://server:443/connect/register")]
    [InlineData(SsraaVersion.V3_0, "https://server/connect/register/")]
    [InlineData(SsraaVersion.V3_0, "https://server/Connect/Register")]
    public async Task Registration_Aud_Variant_Is_Rejected(SsraaVersion version, string aud)
    {
        var pipeline = BuildPipeline(version);

        var response = await Register(pipeline, aud);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(error);
        Assert.Equal(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, error!.Error);
        Assert.Equal(UdapDynamicClientRegistrationErrorDescriptions.InvalidMatchAud, error.ErrorDescription);
    }

    /// <summary>
    /// SSRAA 1.1 keeps the lenient comparison (host, port, path and query compared case-insensitively).
    /// </summary>
    [Theory]
    [InlineData("https://SERVER/connect/register")]
    [InlineData("https://server:443/connect/register")]
    [InlineData("https://server/Connect/Register")]
    public async Task Registration_Aud_Variant_Is_Accepted_Under_V1_1(string aud)
    {
        var pipeline = BuildPipeline(SsraaVersion.V1_1);

        var response = await Register(pipeline, aud);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>
    /// Behind a reverse proxy the request URL differs from the URL clients were given. The aud is accepted
    /// when it exactly equals the advertised registration endpoint (the OpenID discovery custom entry, or the
    /// endpoint derived from Duende's server URLs) and still rejected for any case variant of it.
    /// </summary>
    [Theory]
    [InlineData("http://internal:8080/connect/register", true)]
    [InlineData("https://public.example.com/connect/register", true)]
    [InlineData("https://origin.example.com/connect/register", true)]
    [InlineData("https://PUBLIC.example.com/connect/register", false)]
    [InlineData("https://public.example.com/connect/register/", false)]
    [InlineData("https://other.example.com/connect/register", false)]
    public void Registration_Aud_Matches_Advertised_Endpoint_Behind_A_Proxy(string aud, bool expected)
    {
        var identityServerOptions = new Duende.IdentityServer.Configuration.IdentityServerOptions();
        identityServerOptions.Discovery.CustomEntries.Add(
            OidcConstants.Discovery.RegistrationEndpoint, "https://public.example.com/connect/register");

        var serverUrls = Substitute.For<Duende.IdentityServer.Services.IServerUrls>();
        serverUrls.BaseUrl.Returns("https://origin.example.com");

        var services = new ServiceCollection()
            .AddSingleton(identityServerOptions)
            .AddSingleton(serverUrls)
            .BuildServiceProvider();

        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = "http";
        context.Request.Host = new Microsoft.AspNetCore.Http.HostString("internal:8080");
        context.Request.Path = "/connect/register";

        var accessor = Substitute.For<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);

        var validator = new Udap.Server.Registration.UdapDynamicClientRegistrationValidator(
            Substitute.For<Udap.Common.Certificates.TrustChainValidator>(Substitute.For<ILogger<Udap.Common.Certificates.TrustChainValidator>>(), null),
            new HttpClient(),
            new TestReplayCache(new StubClock()),
            new ServerSettings { SsraaVersion = SsraaVersion.V3_0 },
            accessor,
            new Udap.Server.Validation.Default.DefaultScopeExpander(),
            Substitute.For<Duende.IdentityServer.Stores.IResourceStore>(),
            Substitute.For<ILogger<Udap.Server.Registration.UdapDynamicClientRegistrationValidator>>());

        Assert.Equal(expected, validator.AudienceMatchesRegistrationEndpoint(aud, new Uri(aud)));
    }

    [Theory]
    [InlineData(SsraaVersion.V1_1)]
    [InlineData(SsraaVersion.V2_0)]
    [InlineData(SsraaVersion.V3_0)]
    public async Task Token_Client_Assertion_Exact_Aud_Succeeds(SsraaVersion version)
    {
        var pipeline = BuildPipeline(version);
        var clientCert = LoadClientCert();
        var registration = await RegisterClientCredentials(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, registration.ClientId!, clientCert, UdapAuthServerPipeline.TokenEndpoint);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
    }

    [Theory]
    [InlineData(SsraaVersion.V2_0, "https://server/connect/token/")]
    [InlineData(SsraaVersion.V2_0, "https://SERVER/connect/token")]
    [InlineData(SsraaVersion.V2_0, "https://server:443/connect/token")]
    [InlineData(SsraaVersion.V3_0, "https://server/connect/token/")]
    [InlineData(SsraaVersion.V3_0, "https://SERVER/connect/token")]
    [InlineData(SsraaVersion.V3_0, "https://server:443/connect/token")]
    public async Task Token_Client_Assertion_Aud_Variant_Is_Rejected(SsraaVersion version, string aud)
    {
        var pipeline = BuildPipeline(version);
        var clientCert = LoadClientCert();
        var registration = await RegisterClientCredentials(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, registration.ClientId!, clientCert, aud);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(OidcConstants.TokenErrors.InvalidClient, tokenResponse.Error);
    }

    /// <summary>
    /// SSRAA 1.1 keeps the Microsoft.IdentityModel default of ignoring a trailing slash on the audience.
    /// </summary>
    [Fact]
    public async Task Token_Client_Assertion_Trailing_Slash_Aud_Is_Accepted_Under_V1_1()
    {
        var pipeline = BuildPipeline(SsraaVersion.V1_1);
        var clientCert = LoadClientCert();
        var registration = await RegisterClientCredentials(pipeline, clientCert);

        var tokenResponse = await RequestToken(pipeline, registration.ClientId!, clientCert, "https://server/connect/token/");

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
    }

    /// <summary>
    /// SSRAA 3.0.0 (FHIR-52960): the authorization endpoint accepts both GET and POST for the
    /// authorization code flow. Duende IdentityServer's authorize endpoint supports POST
    /// (application/x-www-form-urlencoded) natively; this pins that behaviour with the UDAP middleware in place.
    /// </summary>
    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public async Task Authorize_Accepts_Get_And_Post_For_Authorization_Code(string method)
    {
        var pipeline = BuildPipeline(SsraaVersion.V3_0);
        var clientCert = LoadClientCert();

        var registrationResponse = await Register(pipeline, UdapAuthServerPipeline.RegistrationEndpoint);
        Assert.Equal(HttpStatusCode.Created, registrationResponse.StatusCode);
        var registration = await registrationResponse.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        await pipeline.LoginAsync("bob");

        var udapClient = pipeline.Resolve<IUdapClient>();
        var pkce = udapClient.GeneratePkce();
        var state = Guid.NewGuid().ToString();

        var url = pipeline.CreateAuthorizeUrl(
            clientId: registration!.ClientId!,
            responseType: "code",
            scope: "openid",
            redirectUri: "https://code_client/callback",
            state: state,
            nonce: Guid.NewGuid().ToString(),
            codeChallenge: pkce.CodeChallenge,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256);

        pipeline.BrowserClient.AllowAutoRedirect = false;

        HttpResponseMessage response;
        if (method == "POST")
        {
            var parameters = QueryHelpers.ParseQuery(new Uri(url).Query)
                .ToDictionary(p => p.Key, p => p.Value.ToString());
            response = await pipeline.BrowserClient.PostAsync(
                UdapAuthServerPipeline.AuthorizeEndpoint,
                new FormUrlEncodedContent(parameters));
        }
        else
        {
            response = await pipeline.BrowserClient.GetAsync(url);
        }

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.StartsWith("https://code_client/callback", response.Headers.Location!.AbsoluteUri);
        var queryParams = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.True(queryParams.ContainsKey("code"));
        Assert.False(queryParams.ContainsKey("error"));
        Assert.Equal(state, queryParams["state"].ToString());

        var tokenRequest = AccessTokenRequestForAuthorizationCodeBuilder.Create(
                registration.ClientId!,
                UdapAuthServerPipeline.TokenEndpoint,
                clientCert,
                "https://code_client/callback",
                queryParams["code"].ToString())
            .Build();
        tokenRequest.CodeVerifier = pkce.CodeVerifier;

        var tokenResponse = await udapClient.ExchangeCodeForTokenResponse(tokenRequest);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.False(string.IsNullOrEmpty(tokenResponse.AccessToken));
    }

    private static X509Certificate2 LoadClientCert()
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile(ClientCertPath, "udap-test");
#else
        return new X509Certificate2(ClientCertPath, "udap-test");
#endif
    }

    private static async Task<HttpResponseMessage> Register(UdapAuthServerPipeline pipeline, string aud)
    {
        var signedSoftwareStatement = UdapDcrBuilderForAuthorizationCode
            .Create(LoadClientCert())
            .WithAudience(aud)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("Test Client")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:test@example.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("openid user/*.read")
            .WithResponseTypes(new List<string> { "code" })
            .WithRedirectUrls(new List<string> { "https://code_client/callback" })
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(signedSoftwareStatement, UdapConstants.UdapVersionsSupportedValue);

        // Always post to the endpoint itself; only the aud in the software statement varies.
        return await pipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));
    }

    private static async Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentials(
        UdapAuthServerPipeline pipeline,
        X509Certificate2 clientCert)
    {
        var udapClient = pipeline.Resolve<IUdapClient>();

        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        {
            RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint
        };

        var registration = await udapClient.RegisterClientCredentialsClient(clientCert, "system/*.read");

        Assert.Null(registration.GetError());

        return registration;
    }

    private static async Task<Duende.IdentityModel.Client.TokenResponse> RequestToken(
        UdapAuthServerPipeline pipeline,
        string clientId,
        X509Certificate2 clientCert,
        string aud)
    {
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(clientId, aud, clientCert)
            .WithScope("system/*.read")
            .Build("RS384");

        // Always post to the token endpoint itself; only the client assertion aud varies.
        clientRequest.Address = UdapAuthServerPipeline.TokenEndpoint;

        return await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
    }

    private static UdapAuthServerPipeline BuildPipeline(SsraaVersion version)
    {
        var pipeline = new UdapAuthServerPipeline();

#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        var serverSettings = new ServerSettings
        {
            DefaultUserScopes = "user/*.read",
            DefaultSystemScopes = "system/*.read",
            SsraaVersion = version,
            RequireConsent = false
        };

        pipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(serverSettings);
            services.AddSingleton<IOptionsMonitor<ServerSettings>>(new OptionsMonitorForTests<ServerSettings>(serverSettings));

            services.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "Mock Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com" }
                }));
        };

        pipeline.OnPreConfigureServices += (_, services) =>
        {
            services.AddSingleton(pipeline.Clients);
            services.AddScoped<IUdapClient>(sp => new UdapClient(
                pipeline.BackChannelClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        pipeline.Initialize(enableLogging: true);
        pipeline.BrowserClient.AllowAutoRedirect = false;

        pipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, "udap://fhirlabs.net")
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Enabled = true,
                    Intermediates =
                    [
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    ]
                }
            ]
        });

        pipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        pipeline.IdentityScopes.Add(new IdentityResources.Profile());
        pipeline.ApiScopes.Add(new ApiScope("user/*.read"));
        pipeline.ApiScopes.Add(new ApiScope("system/*.read"));

        pipeline.Users.Add(new TestUser
        {
            SubjectId = "bob",
            Username = "bob",
            Claims =
            [
                new Claim("name", "Bob Loblaw"),
                new Claim("email", "bob@loblaw.com")
            ]
        });

        return pipeline;
    }
}

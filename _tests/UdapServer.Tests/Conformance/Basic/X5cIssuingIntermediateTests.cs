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
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
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
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// Registration and token requests whose x5c header carries the client certificate followed by the
/// intermediate that issued it, and the <see cref="ServerSettings.RequireIssuingIntermediateInX5c"/> option.
/// </summary>
[Collection("Udap.Auth.Server")]
public class X5cIssuingIntermediateTests
{
    private const string Community = "udap://fhirlabs.net";
    private const string Scope = "system/Patient.rs";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RegisterAndToken_WithLeafAndIntermediate_Succeeds(bool requireIntermediate)
    {
        var pipeline = BuildPipeline(requireIntermediate);
        var chain = LoadClientChain();

        var response = await Register(pipeline, chain);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.NotNull(document?.ClientId);

        var tokenResponse = await RequestToken(pipeline, document!.ClientId!, chain);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.NotNull(tokenResponse.AccessToken);
    }

    [Fact]
    public async Task Register_LeafOnly_OptionOff_Succeeds()
    {
        var pipeline = BuildPipeline(requireIntermediate: false);
        var leaf = LoadClientChain()[0];

        var response = await Register(pipeline, [leaf]);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        var tokenResponse = await RequestToken(pipeline, document!.ClientId!, [leaf]);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);
    }

    [Fact]
    public async Task Register_LeafOnly_OptionOn_IsRejected()
    {
        var pipeline = BuildPipeline(requireIntermediate: true);
        var leaf = LoadClientChain()[0];

        var response = await Register(pipeline, [leaf]);

        await AssertMissingIntermediate(response);
    }

    [Fact]
    public async Task Register_LeafAndUnrelatedIntermediate_OptionOn_IsRejected()
    {
        var pipeline = BuildPipeline(requireIntermediate: true);
        var leaf = LoadClientChain()[0];
#if NET9_0_OR_GREATER
        var unrelated = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/intermediateLocalhostCert.cer");
#else
        var unrelated = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert.cer");
#endif

        var response = await Register(pipeline, [leaf, unrelated]);

        await AssertMissingIntermediate(response);
    }

    [Fact]
    public async Task Token_LeafOnly_OptionOn_IsRejected()
    {
        var pipeline = BuildPipeline(requireIntermediate: true);
        var chain = LoadClientChain();

        var response = await Register(pipeline, chain);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        var tokenResponse = await RequestToken(pipeline, document!.ClientId!, [chain[0]]);

        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    [Fact]
    public async Task UdapClient_PassedLeafWithItsCaCertificates_SendsLeafAndIntermediate()
    {
        var pipeline = BuildPipeline(requireIntermediate: true);
        var pfx = LoadClientPfx();

        var udapClient = pipeline.Resolve<IUdapClient>();
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        {
            RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint
        };

        // The whole PKCS#12 content: leaf, intermediate and root. Only the leaf signs, the root is never sent.
        var result = await udapClient.RegisterClientCredentialsClient(pfx, Scope);

        Assert.Null(result.GetError());
        Assert.NotNull(result.ClientId);
    }

    private static async Task AssertMissingIntermediate(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(error);
        Assert.Equal(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, error!.Error);
        Assert.Equal(UdapDynamicClientRegistrationErrorDescriptions.X5cMissingIssuingIntermediate, error.ErrorDescription);
    }

    private static List<X509Certificate2> LoadClientPfx()
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12CollectionFromFile("CertStore/issued/fhirlabs.net.client.pfx", "udap-test", X509KeyStorageFlags.Exportable).ToList();
#else
        var collection = new X509Certificate2Collection();
        collection.Import("CertStore/issued/fhirlabs.net.client.pfx", "udap-test", X509KeyStorageFlags.Exportable);
        return collection.ToList();
#endif
    }

    /// <summary>The client certificate followed by the intermediate that issued it.</summary>
    private static List<X509Certificate2> LoadClientChain()
    {
        var pfx = LoadClientPfx();
        var leaf = pfx.Single(c => c.HasPrivateKey && !X5cChain.IsCertificateAuthority(c));
        var chain = X5cChain.Build(leaf, pfx);

        Assert.Equal(2, chain.Count);

        return chain;
    }

    private static async Task<HttpResponseMessage> Register(UdapAuthServerPipeline pipeline, List<X509Certificate2> x5c)
    {
        var signedSoftwareStatement = UdapDcrBuilderForClientCredentials
            .Create(x5c)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("x5c intermediate test")
            .WithLogoUri("https://avatars.githubusercontent.com/u/77421324?s=48&v=4")
            .WithContacts(new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com" })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope(Scope)
            .BuildSoftwareStatement();

        var requestBody = new UdapRegisterRequest(signedSoftwareStatement, UdapConstants.UdapVersionsSupportedValue);

        return await pipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.RegistrationEndpoint,
            new StringContent(JsonSerializer.Serialize(requestBody), new MediaTypeHeaderValue("application/json")));
    }

    private static async Task<Duende.IdentityModel.Client.TokenResponse> RequestToken(
        UdapAuthServerPipeline pipeline,
        string clientId,
        List<X509Certificate2> x5c)
    {
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                clientId,
                IdentityServerPipeline.TokenEndpoint,
                x5c)
            .WithScope(Scope)
            .Build("RS384");

        return await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
    }

    private static UdapAuthServerPipeline BuildPipeline(bool requireIntermediate)
    {
        var serverSettings = new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            RequireIssuingIntermediateInX5c = requireIntermediate
        };

        var pipeline = new UdapAuthServerPipeline();

#if NET9_0_OR_GREATER
        var sureFhirLabsAnchor = X509CertificateLoader.LoadCertificateFromFile("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = X509CertificateLoader.LoadCertificateFromFile("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#else
        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");
#endif

        pipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(serverSettings);
            services.AddSingleton<IOptionsMonitor<ServerSettings>>(
                new OptionsMonitorForTests<ServerSettings>(serverSettings));

            services.AddSingleton<IOptionsMonitor<UdapClientOptions>>(
                new OptionsMonitorForTests<UdapClientOptions>(
                    new UdapClientOptions
                    {
                        ClientName = "Mock Client",
                        Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com" }
                    }));

            services.AddScoped<IUdapClient>(sp => new UdapClient(
                pipeline.BrowserClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));
        };

        pipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(pipeline.Clients);
        };

        pipeline.Initialize(enableLogging: true);
        pipeline.BrowserClient.AllowAutoRedirect = false;

        pipeline.Communities.Add(new Community
        {
            Name = Community,
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(sureFhirLabsAnchor, Community)
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Enabled = true,
                    Intermediates = new List<Intermediate>
                    {
                        new Intermediate(intermediateCert)
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Enabled = true
                        }
                    }
                }
            ]
        });

        pipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes(Scope));

        return pipeline;
    }
}

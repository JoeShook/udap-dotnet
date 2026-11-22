#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Org.BouncyCastle.X509;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using Udap.Tefca.Model;
using Udap.Tefca.Server;
using UdapServer.Tests.Common;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// One authorization server with a TEFCA community and a non-TEFCA community.
/// TEFCA clients must send x5c = [client certificate, issuing intermediate] and their chain is built without
/// AIA downloads; the non-TEFCA community keeps the base UDAP behaviour (leaf-only x5c, chain completed via AIA).
/// </summary>
[Collection("Udap.Auth.Server")]
public class X5cIssuingIntermediateTests
{
    private const string FhirLabsCommunity = "udap://fhirlabs.net";
    private const string TefcaCommunity = TefcaConstants.CommunityUri;
    private const string Scope = "system/Patient.rs";
    private const string FhirLabsAiaFile = "SureFhirLabs_Intermediate.cer";
    private const string TefcaAiaFile = "TEFCA_Test_Intermediate.cer";

    [Fact]
    public async Task NonTefcaCommunity_LeafOnly_RegistersAndGetsToken_ThroughAia()
    {
        var (pipeline, downloads) = BuildPipeline();
        var leaf = LoadChain(FhirLabsPfx)[0];

        var response = await Register(pipeline, [leaf]);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal(FhirLabsCommunity, ClientCommunity(pipeline, document!.ClientId!));
        Assert.Contains(downloads.Urls, url => url.EndsWith(FhirLabsAiaFile));

        var tokenResponse = await RequestToken(pipeline, document.ClientId!, [leaf]);
        Assert.False(tokenResponse.IsError, tokenResponse.Error);
    }

    [Fact]
    public async Task NonTefcaCommunity_LeafAndIntermediate_Registers()
    {
        var (pipeline, _) = BuildPipeline();

        var response = await Register(pipeline, LoadChain(FhirLabsPfx));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task TefcaCommunity_LeafAndIntermediate_RegistersAndGetsToken_WithoutAia()
    {
        // The TEFCA intermediate is not configured on the server: the chain can only come from x5c.
        var (pipeline, downloads) = BuildPipeline(configureTefcaIntermediate: false);
        var chain = LoadChain(TefcaPfx);

        var response = await Register(pipeline, chain);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();
        Assert.Equal(TefcaCommunity, ClientCommunity(pipeline, document!.ClientId!));

        var tokenResponse = await RequestToken(pipeline, document.ClientId!, chain, TefcaB2B());
        Assert.False(tokenResponse.IsError, tokenResponse.Error);

        Assert.Empty(downloads.Urls);
    }

    [Fact]
    public async Task TefcaCommunity_LeafOnly_IsRejected_WithoutAia()
    {
        // With the TEFCA intermediate configured the server completes the chain offline, so it knows the
        // client is in the TEFCA community and can say why it is rejected.
        var (pipeline, downloads) = BuildPipeline(configureTefcaIntermediate: true);
        var leaf = LoadChain(TefcaPfx)[0];

        var response = await Register(pipeline, [leaf]);

        await AssertMissingIntermediate(response);
        Assert.Empty(downloads.Urls);
    }

    [Fact]
    public async Task TefcaCommunity_LeafOnly_UnknownIntermediate_IsUntrusted()
    {
        // Without the intermediate anywhere, the server cannot tell the client is in the TEFCA community.
        // It tries the non-TEFCA communities as before; the TEFCA anchor is not offered to that attempt,
        // so the client is never trusted through an AIA-completed chain.
        var (pipeline, _) = BuildPipeline(configureTefcaIntermediate: false);
        var leaf = LoadChain(TefcaPfx)[0];

        var response = await Register(pipeline, [leaf]);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.Equal(UdapDynamicClientRegistrationErrorDescriptions.UntrustedCertificate, error!.ErrorDescription);
    }

    [Fact]
    public async Task TefcaCommunity_LeafAndUnrelatedIntermediate_IsRejected()
    {
        var (pipeline, downloads) = BuildPipeline(configureTefcaIntermediate: true);
        var leaf = LoadChain(TefcaPfx)[0];
        var unrelated = LoadChain(FhirLabsPfx)[1];

        var response = await Register(pipeline, [leaf, unrelated]);

        await AssertMissingIntermediate(response);
        Assert.Empty(downloads.Urls);
    }

    [Fact]
    public async Task TefcaCommunity_TokenWithLeafOnly_IsRejected_WithoutAia()
    {
        var (pipeline, downloads) = BuildPipeline(configureTefcaIntermediate: false);
        var chain = LoadChain(TefcaPfx);

        var response = await Register(pipeline, chain);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        var tokenResponse = await RequestToken(pipeline, document!.ClientId!, [chain[0]], TefcaB2B());

        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Empty(downloads.Urls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Token_CommunityCannotBeResolved_IsRejected_OnlyWhenAPolicyIsRegistered(bool addTefcaValidation)
    {
        var (pipeline, _) = BuildPipeline(addTefcaValidation: addTefcaValidation);
        var leaf = LoadChain(FhirLabsPfx)[0];

        var response = await Register(pipeline, [leaf]);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationDocument>();

        // The registration's community id no longer resolves to a community name.
        pipeline.Communities.Single(c => c.Name == FhirLabsCommunity).Name = string.Empty;

        var tokenResponse = await RequestToken(pipeline, document!.ClientId!, [leaf]);

        if (addTefcaValidation)
        {
            Assert.True(tokenResponse.IsError);
            Assert.Equal("invalid_client", tokenResponse.Error);
        }
        else
        {
            Assert.False(tokenResponse.IsError, tokenResponse.Error);
        }
    }

    [Fact]
    public async Task TefcaCommunity_OptOut_LeafOnly_Registers_ThroughAia()
    {
        var (pipeline, downloads) = BuildPipeline(configureTefcaIntermediate: false, requireIssuingIntermediate: false);
        var leaf = LoadChain(TefcaPfx)[0];

        var response = await Register(pipeline, [leaf]);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Contains(downloads.Urls, url => url.EndsWith(TefcaAiaFile));
    }

    [Fact]
    public async Task UdapClient_GivenWholePkcs12_SendsLeafAndIntermediate()
    {
        var (pipeline, downloads) = BuildPipeline(configureTefcaIntermediate: false);

        var udapClient = pipeline.Resolve<IUdapClient>();
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        {
            RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint
        };

        // Leaf, intermediate and root. Only the leaf signs; the TEFCA community accepts it only if x5c carries the intermediate.
        var result = await udapClient.RegisterClientCredentialsClient(LoadPfx(TefcaPfx), Scope);

        Assert.Null(result.GetError());
        Assert.Empty(downloads.Urls);
    }

    private const string FhirLabsPfx = "CertStore/issued/fhirlabs.net.client.pfx";
    private const string TefcaPfx = "CertStore/issued/fhirlabs.net.tefca.client.pfx";

    private static HL7B2BAuthorizationExtension TefcaB2B() => new()
    {
        SubjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890",
        OrganizationId = "https://fhirlabs.net/fhir/r4",
        OrganizationName = "FhirLabs",
        PurposeOfUse = [$"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#{TefcaConstants.ExchangePurposeCodes.TefcaRequiredTreatment}"]
    };

    private static string? ClientCommunity(UdapAuthServerPipeline pipeline, string clientId)
    {
        var client = pipeline.Clients.Single(c => c.ClientId == clientId);
        var communityId = client.ClientSecrets
            .Single(s => s.Type == Udap.Server.Storage.UdapServerConstants.SecretTypes.UDAP_COMMUNITY).Value;

        return pipeline.Communities.Single(c => c.Id.ToString() == communityId).Name;
    }

    private static async Task AssertMissingIntermediate(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<UdapDynamicClientRegistrationErrorResponse>();
        Assert.NotNull(error);
        Assert.Equal(UdapDynamicClientRegistrationErrors.InvalidSoftwareStatement, error!.Error);
        Assert.Equal(UdapDynamicClientRegistrationErrorDescriptions.X5cMissingIssuingIntermediate, error.ErrorDescription);
    }

    private static List<X509Certificate2> LoadPfx(string path)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12CollectionFromFile(path, "udap-test", X509KeyStorageFlags.Exportable).ToList();
#else
        var collection = new X509Certificate2Collection();
        collection.Import(path, "udap-test", X509KeyStorageFlags.Exportable);
        return collection.ToList();
#endif
    }

    /// <summary>The client certificate followed by the intermediate that issued it.</summary>
    private static List<X509Certificate2> LoadChain(string path)
    {
        var pfx = LoadPfx(path);
        var leaf = pfx.Single(c => c.HasPrivateKey && !X5cChain.IsCertificateAuthority(c));
        var chain = X5cChain.Build(leaf, pfx);

        Assert.Equal(2, chain.Count);

        return chain;
    }

    private static X509Certificate2 LoadCer(string path)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificateFromFile(path);
#else
        return new X509Certificate2(path);
#endif
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
        List<X509Certificate2> x5c,
        HL7B2BAuthorizationExtension? b2b = null)
    {
        var builder = AccessTokenRequestForClientCredentialsBuilder.Create(
                clientId,
                IdentityServerPipeline.TokenEndpoint,
                x5c)
            .WithScope(Scope);

        if (b2b != null)
        {
            builder.WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b);
        }

        return await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(builder.Build("RS384"));
    }

    private static (UdapAuthServerPipeline Pipeline, RecordingDownloadCache Downloads) BuildPipeline(
        bool configureTefcaIntermediate = true,
        bool requireIssuingIntermediate = true,
        bool addTefcaValidation = true)
    {
        var serverSettings = new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1
        };

        var downloads = new RecordingDownloadCache();
        var pipeline = new UdapAuthServerPipeline();

        pipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(serverSettings);
            services.AddSingleton<IOptionsMonitor<ServerSettings>>(
                new OptionsMonitorForTests<ServerSettings>(serverSettings));

            // AIA downloads go through the recording cache, which serves the intermediates from disk.
            services.AddSingleton(sp => new TrustChainValidator(
                TrustChainValidator.DefaultProblemFlags,
                false,
                sp.GetRequiredService<ILogger<TrustChainValidator>>(),
                downloads));

            if (addTefcaValidation)
            {
                services.AddUdapTefcaValidation(options => options.RequireIssuingIntermediateInX5c = requireIssuingIntermediate);
            }

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

        // No intermediate configured: the server completes this chain through AIA.
        pipeline.Communities.Add(BuildCommunity(1, FhirLabsCommunity, isDefault: true,
            LoadCer("CertStore/anchors/SureFhirLabs_CA.cer"), intermediate: null));

        pipeline.Communities.Add(BuildCommunity(2, TefcaCommunity, isDefault: false,
            LoadCer("CertStore/anchors/TEFCA_Test_CA.cer"),
            configureTefcaIntermediate ? LoadCer("CertStore/intermediates/TEFCA_Test_Intermediate.cer") : null));

        pipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes(Scope));

        return (pipeline, downloads);
    }

    private static Community BuildCommunity(int id, string name, bool isDefault, X509Certificate2 anchor, X509Certificate2? intermediate)
    {
        return new Community
        {
            Id = id,
            Name = name,
            Enabled = true,
            Default = isDefault,
            Anchors =
            [
                new Anchor(anchor, name)
                {
                    CommunityId = id,
                    BeginDate = anchor.NotBefore.ToUniversalTime(),
                    EndDate = anchor.NotAfter.ToUniversalTime(),
                    Name = anchor.Subject,
                    Enabled = true,
                    Intermediates = intermediate == null
                        ? []
                        : new List<Intermediate>
                        {
                            new Intermediate(intermediate)
                            {
                                BeginDate = intermediate.NotBefore.ToUniversalTime(),
                                EndDate = intermediate.NotAfter.ToUniversalTime(),
                                Name = intermediate.Subject,
                                Enabled = true
                            }
                        }
                }
            ]
        };
    }

    /// <summary>
    /// Records every AIA download and serves the requested intermediate from the test certificate store.
    /// </summary>
    private sealed class RecordingDownloadCache : ICertificateDownloadCache
    {
        public ConcurrentQueue<string> Urls { get; } = new();

        public Task<X509Certificate2?> GetIntermediateCertificateAsync(string url, CancellationToken cancellationToken = default)
        {
            Urls.Enqueue(url);
            var path = Path.Combine("CertStore/intermediates", Path.GetFileName(new Uri(url).AbsolutePath));

            return Task.FromResult(File.Exists(path) ? LoadCer(path) : null);
        }

        public Task<X509Crl?> GetCrlAsync(string url, CancellationToken cancellationToken = default) => Task.FromResult<X509Crl?>(null);

        public Task RemoveIntermediateAsync(string url, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RemoveCrlAsync(string url, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

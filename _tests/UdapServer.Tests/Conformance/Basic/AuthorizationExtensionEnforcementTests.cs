#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel.Client;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client.Client;
using Udap.Client.Client.Extensions;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

[Collection("Udap.Auth.Server")]
public class AuthorizationExtensionEnforcementTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public AuthorizationExtensionEnforcementTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task TokenRequest_WithRequiredB2B_WithValidExtension_Succeeds()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        var b2b = new HL7B2BAuthorizationExtension
        {
            SubjectId = "urn:oid:2.16.840.1.113883.4.6#1234567890",
            OrganizationId = "https://fhirlabs.net/fhir/r4",
            OrganizationName = "FhirLabs",
            PurposeOfUse = new List<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b)
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task TokenRequest_WithRequiredB2B_WithoutExtension_Fails()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        // Token request WITHOUT extension
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    [Fact]
    public async Task TokenRequest_WithRequiredB2B_WithInvalidExtension_MissingOrganizationId_Fails()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
        });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        // B2B extension with missing organization_id
        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = null,
            PurposeOfUse = new List<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b)
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    [Fact]
    public async Task TokenRequest_NoRequiredExtensions_WithoutExtension_Succeeds()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            AuthorizationExtensionsRequired = null
        });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        // Token request without any extension — should work when nothing is required
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task TokenRequest_CommunityOverride_RequiresB2B_WithoutExtension_Fails()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            AuthorizationExtensionsRequired = null,
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://fhirlabs.net",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
                }
            ]
        });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        // Token request without extension — community requires it
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.HttpStatusCode);
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    [Fact]
    public async Task TokenRequest_CommunityOverride_RequiresB2B_WithValidExtension_Succeeds()
    {
        var pipeline = BuildPipeline(new ServerSettings
        {
            DefaultSystemScopes = "udap",
            DefaultUserScopes = "udap",
            SsraaVersion = SsraaVersion.V1_1,
            AuthorizationExtensionsRequired = null,
            CommunitySettings =
            [
                new CommunityServerSettings
                {
                    Community = "udap://fhirlabs.net",
                    AuthorizationExtensionsRequired = [UdapConstants.UdapAuthorizationExtensions.Hl7B2B]
                }
            ]
        });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        var b2b = new HL7B2BAuthorizationExtension
        {
            OrganizationId = "https://fhirlabs.net/fhir/r4",
            OrganizationName = "FhirLabs",
            PurposeOfUse = new List<string> { "urn:oid:2.16.840.1.113883.5.8#TREAT" }
        };

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .WithExtension(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, b2b)
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.False(tokenResponse.IsError, tokenResponse.Error);
        Assert.Equal("system/Patient.rs", tokenResponse.Scope);
    }

    [Fact]
    public async Task TokenRequest_CustomValidator_Overrides_DefaultBehavior()
    {
        var customValidator = Substitute.For<IUdapAuthorizationExtensionValidator>();
        customValidator.ValidateAsync(Arg.Any<UdapAuthorizationExtensionValidationContext>())
            .Returns(AuthorizationExtensionValidationResult.Failure("custom_error", "Custom validator rejected"));

        var pipeline = BuildPipeline(
            new ServerSettings
            {
                DefaultSystemScopes = "udap",
                DefaultUserScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            },
            configureServices: services =>
            {
                // Replace default validator with custom one BEFORE AddUdapServer registers it
                services.AddSingleton<IUdapAuthorizationExtensionValidator>(customValidator);
            });

        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");
        var regResult = await RegisterClient(pipeline, clientCert);

        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                regResult.ClientId,
                IdentityServerPipeline.TokenEndpoint,
                clientCert)
            .WithScope("system/Patient.rs")
            .Build("RS384");

        var tokenResponse = await pipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);

        Assert.True(tokenResponse.IsError);
        Assert.Equal("invalid_client", tokenResponse.Error);
    }

    #region Helpers

    private UdapAuthServerPipeline BuildPipeline(
        ServerSettings serverSettings,
        Action<IServiceCollection>? configureServices = null)
    {
        var pipeline = new UdapAuthServerPipeline();

        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

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
                        Contacts = new HashSet<string>
                        {
                            "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                        }
                    }));

            services.AddScoped<IUdapClient>(sp => new UdapClient(
                pipeline.BrowserClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

            configureServices?.Invoke(services);
        };

        pipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(pipeline.Clients);
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

        pipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        pipeline.IdentityScopes.Add(new IdentityResources.Profile());
        pipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes("system/Patient.rs"));

        return pipeline;
    }

    private static async Task<UdapDynamicClientRegistrationDocument> RegisterClient(
        UdapAuthServerPipeline pipeline,
        X509Certificate2 clientCert)
    {
        var udapClient = pipeline.Resolve<IUdapClient>();

        udapClient.UdapServerMetaData = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
        {
            RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint
        };

        var regResult = await udapClient.RegisterClientCredentialsClient(
            clientCert,
            "system/Patient.rs");

        Assert.Null(regResult.GetError());

        return regResult;
    }

    #endregion
}

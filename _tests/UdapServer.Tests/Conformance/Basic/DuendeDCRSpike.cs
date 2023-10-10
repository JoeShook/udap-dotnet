using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Configuration.Configuration;
using Duende.IdentityServer.Configuration.Models.DynamicClientRegistration;
using Duende.IdentityServer.Configuration.RequestProcessing;
using Duende.IdentityServer.Configuration.Validation.DynamicClientRegistration;
using Duende.IdentityServer.Models;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Udap.Client.Configuration;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Registration;
using Udap.Model.Statement;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using Udap.Util.Extensions;
using UdapServer.Tests.Common;
using Xunit.Abstractions;

namespace UdapServer.Tests.Conformance.Basic;

public class DuendeDCRSpike
{

    private readonly ITestOutputHelper _testOutputHelper;
    private UdapAuthServerPipeline _mockPipeline = new UdapAuthServerPipeline();

    public DuendeDCRSpike(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        var sureFhirLabsAnchor = new X509Certificate2("CertStore/anchors/SureFhirLabs_CA.cer");
        var intermediateCert = new X509Certificate2("CertStore/intermediates/SureFhirLabs_Intermediate.cer");

        var anchorCommunity2 = new X509Certificate2("CertStore/anchors/caLocalhostCert2.cer");
        var intermediateCommunity2 = new X509Certificate2("CertStore/intermediates/intermediateLocalhostCert2.cer");

        _mockPipeline.OnPostConfigureServices += s =>
        {
            s.AddSingleton<ServerSettings>(new ServerSettings
            {
                ServerSupport = ServerSupport.UDAP,
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap"
            });

            s.AddSingleton<UdapClientOptions>(new UdapClientOptions
            {
                ClientName = "Mock Client",
                Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
            });


            s.AddIdentityServerConfiguration(opt => { }).AddInMemoryClientConfigurationStore();

            s.AddTransient<DynamicClientRegistrationEndpoint>();
            s.AddTransient(
                resolver => resolver.GetRequiredService<IOptionsMonitor<IdentityServerConfigurationOptions>>().CurrentValue);
            s.TryAddTransient<IDynamicClientRegistrationValidator, DynamicClientRegistrationValidator>();
            s.TryAddTransient<IDynamicClientRegistrationRequestProcessor, DynamicClientRegistrationRequestProcessor>();
        };

        _mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            // This registers Clients as List<Client> so downstream I can pick it up in InMemoryUdapClientRegistrationStore
            // Duende's AddInMemoryClients extension registers as IEnumerable<Client> and is used in InMemoryClientStore as readonly.
            // It was not intended to work with the concept of a dynamic client registration.
            s.AddSingleton(_mockPipeline.Clients);
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockPipeline.Communities.Add(new Community
        {
            Name = "udap://fhirlabs.net",
            Enabled = true,
            Default = true,
            Anchors = new[]
            {
                new Anchor
                {
                    BeginDate = sureFhirLabsAnchor.NotBefore.ToUniversalTime(),
                    EndDate = sureFhirLabsAnchor.NotAfter.ToUniversalTime(),
                    Name = sureFhirLabsAnchor.Subject,
                    Community = "udap://fhirlabs.net",
                    Certificate = sureFhirLabsAnchor.ToPemFormat(),
                    Thumbprint = sureFhirLabsAnchor.Thumbprint,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate
                        {
                            BeginDate = intermediateCert.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCert.NotAfter.ToUniversalTime(),
                            Name = intermediateCert.Subject,
                            Certificate = intermediateCert.ToPemFormat(),
                            Thumbprint = intermediateCert.Thumbprint,
                            Enabled = true
                        }
                    }
                }
            }
        });

        _mockPipeline.Communities.Add(new Community
        {
            Name = "localhost_fhirlabs_community2",
            Enabled = true,
            Default = false,
            Anchors = new[]
            {
                new Anchor
                {
                    BeginDate = anchorCommunity2.NotBefore.ToUniversalTime(),
                    EndDate = anchorCommunity2.NotAfter.ToUniversalTime(),
                    Name = anchorCommunity2.Subject,
                    Community = "localhost_fhirlabs_community2",
                    Certificate = anchorCommunity2.ToPemFormat(),
                    Thumbprint = anchorCommunity2.Thumbprint,
                    Enabled = true,
                    Intermediates = new List<Intermediate>()
                    {
                        new Intermediate
                        {
                            BeginDate = intermediateCommunity2.NotBefore.ToUniversalTime(),
                            EndDate = intermediateCommunity2.NotAfter.ToUniversalTime(),
                            Name = intermediateCommunity2.Subject,
                            Certificate = intermediateCommunity2.ToPemFormat(),
                            Thumbprint = intermediateCommunity2.Thumbprint,
                            Enabled = true
                        }
                    }
                }
            }
        });


        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.IdentityScopes.Add(new IdentityResources.Profile());
        _mockPipeline.ApiScopes.AddRange(new SmartV2Expander().ExpandToApiScopes("system/Patient.rs"));
        _mockPipeline.ApiScopes.AddRange(new SmartV2Expander().ExpandToApiScopes(" system/Appointment.rs"));
        
    }

    /// <summary>
    /// Experiment with the possibility of using the new Duende DCR endpoint.
    ///
    /// Components involved in Duende Dynamic Client Registration
    ///
    /// - DynamicClientRegistrationEndpoint
    /// - IdentityServerConfigurationOptions
    /// - IDynamicClientRegistrationValidator
    /// - IDynamicClientRegistrationRequestProcessor 
    /// - IDynamicClientRegistrationResponseGenerator
    /// - ClientConfigurationStore, maybe not new.  Basically access to client table
    ///
    /// Below is just a simple registration to see what things look like.
    ///
    /// Reasons not to move forward with Duende DCR yet.
    ///
    /// 1. When including a software statement, the metadata in the software statement is not included as
    ///    top-level client metadata values in the DynamicClientRegistrationResponse.  This is required as
    ///    documented in RFC 7591 section 3.2.1.
    ///
    /// 2. Cannot add properties to DynamicClientRegistrationRequest.  This is required to support UDAP
    ///    which looks like the following:
    ///
    ///         POST /register HTTP/1.1
    ///         Host: as.example.com
    ///         Content-type: application/json
    /// 
    ///         {
    ///             "software_statement" : "{signed software statement}",
    ///             "certifications" : [array of one or more signed JWTs],
    ///             "udap" : "1"
    ///         }
    ///
    ///     certifications and udap client metadata would need to be added.
    ///     Note:  UDAP DCR section 3 says, "additional registration parameters SHOULD NOT appear at the top level of the submitted JSON object"
    ///
    /// 
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task RegisterWithNewDuendeDCR()
    {
        var clientCert = new X509Certificate2("CertStore/issued/fhirlabs.net.client.pfx", "udap-test");

        var document = UdapDcrBuilderForClientCredentials
            .Create(clientCert)
            .WithAudience(UdapAuthServerPipeline.RegistrationEndpoint)
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("mock test")
            .WithContacts(new HashSet<string>
            {
                "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
            })
            .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
            .WithScope("system/Patient.rs")
            .Build();

        var signedSoftwareStatement =
            SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
                .Create(clientCert, document)
                .Build();

        var request = new DynamicClientRegistrationRequest
        {
            GrantTypes = new[] { "client_credentials" },
            ClientName = "test",
            ClientUri = new Uri("https://example.com"),
            Scope = "system/Patient.rs",
            SoftwareStatement = signedSoftwareStatement
        };

        var requestBody = new UdapRegisterRequest
        (
            signedSoftwareStatement,
            UdapConstants.UdapVersionsSupportedValue,
            new string[] { }
        );

        var regResponse = await _mockPipeline.BrowserClient.PostAsync(
            UdapAuthServerPipeline.DCREndpoint,
            new StringContent(JsonSerializer.Serialize(request), new MediaTypeHeaderValue("application/json")));

        regResponse.StatusCode.Should().Be(HttpStatusCode.Created, await regResponse.Content.ReadAsStringAsync());
        var regDocumentResult = await regResponse.Content.ReadFromJsonAsync<DynamicClientRegistrationResponse>();

        _testOutputHelper.WriteLine(JsonSerializer.Serialize(regDocumentResult, new JsonSerializerOptions { WriteIndented = true}));
    }
}

#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Client;
using Udap.Client.Configuration;
using Udap.Client.Extensions;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Server.Configuration;
using Udap.Server.Validation;
using UdapServer.Tests.Common;
using Xunit.Abstractions;
using ZiggyCreatures.Caching.Fusion;

namespace UdapServer.Tests.Conformance.Basic;

/// <summary>
/// Registration validates the client certificate's chain, CRL included, only at registration time.
/// A certificate can be revoked afterwards, and from then on the client must stop getting tokens.
/// These tests turn on revocation checking (the shared pipeline disables it), serve the CRL from an
/// in-memory handler, and replace the CRL after a successful registration.
/// </summary>
[Collection("Udap.Auth.Server")]
public class RevokedAfterRegistrationTests : IDisposable
{
    private const string CommunityName = "udap://revocation.test";
    private const string CrlUrl = "http://crl.revocation.test/root.crl";
    private const string ClientSan = "https://client.revocation.test/fhir";
    private const string Scope = "system/Patient.rs";

    private readonly ITestOutputHelper _testOutputHelper;
    private readonly UdapAuthServerPipeline _mockPipeline = new();
    private readonly CrlHttpHandler _crlHandler = new();

    private readonly RSA _rootKey;
    private readonly X509Certificate2 _rootCert;
    private readonly X509Certificate2 _clientCert;

    public RevokedAfterRegistrationTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;

        _rootKey = RSA.Create(2048);
        _rootCert = CreateRootCa(_rootKey);
        _clientCert = CreateClientCertificate(_rootCert);

        _mockPipeline.OnPostConfigureServices += services =>
        {
            services.AddSingleton(new ServerSettings
            {
                DefaultUserScopes = "udap",
                DefaultSystemScopes = "udap",
                SsraaVersion = SsraaVersion.V1_1
            });

            services.AddSingleton<IOptionsMonitor<UdapClientOptions>>(new OptionsMonitorForTests<UdapClientOptions>(
                new UdapClientOptions
                {
                    ClientName = "Revocation Test Client",
                    Contacts = new HashSet<string> { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" }
                })
            );

            services.AddScoped<IUdapClient>(sp => new UdapClient(
                _mockPipeline.BrowserClient,
                sp.GetRequiredService<UdapClientDiscoveryValidator>(),
                sp.GetRequiredService<IOptionsMonitor<UdapClientOptions>>(),
                sp.GetRequiredService<ILogger<UdapClient>>()));

            //
            // The shared pipeline turns revocation checking off. Turn it on, and download CRLs through
            // the real FusionCache-backed cache with an HttpClient that serves this test's CRL.
            //
            services.AddSingleton<ICertificateDownloadCache>(sp => new CertificateDownloadCache(
                sp.GetRequiredService<IFusionCacheProvider>(),
                new HttpClient(_crlHandler),
                sp.GetRequiredService<ILogger<CertificateDownloadCache>>()));

            services.AddSingleton(sp => new TrustChainValidator(
                TrustChainValidator.DefaultProblemFlags,
                true,
                sp.GetRequiredService<ILogger<TrustChainValidator>>(),
                sp.GetRequiredService<ICertificateDownloadCache>()));
        };

        _mockPipeline.OnPreConfigureServices += (_, s) =>
        {
            s.AddSingleton(_mockPipeline.Clients);
        };

        _mockPipeline.Initialize(enableLogging: true);
        _mockPipeline.BrowserClient.AllowAutoRedirect = false;

        _mockPipeline.Communities.Add(new Community
        {
            Name = CommunityName,
            Enabled = true,
            Default = true,
            Anchors =
            [
                new Anchor(_rootCert, CommunityName)
                {
                    BeginDate = _rootCert.NotBefore.ToUniversalTime(),
                    EndDate = _rootCert.NotAfter.ToUniversalTime(),
                    Name = _rootCert.Subject,
                    Enabled = true
                }
            ]
        });

        _mockPipeline.IdentityScopes.Add(new IdentityResources.OpenId());
        _mockPipeline.ApiScopes.AddRange(new HL7SmartScopeExpander().ExpandToApiScopes(Scope));
    }

    /// <summary>
    /// The CRL downloaded at registration is cached until its nextUpdate. Once it expires the next
    /// token request downloads the new CRL, sees the revocation and rejects the client.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_Token_Rejected_After_Revocation_Once_Cached_Crl_Expires()
    {
        var crlLifetime = TimeSpan.FromSeconds(5);
        var firstCrlNextUpdate = DateTimeOffset.UtcNow.Add(crlLifetime);
        _crlHandler.Crl = BuildCrl(crlNumber: 1, firstCrlNextUpdate, revokeClient: false);

        var registration = await RegisterClientCredentialsClient();

        var tokenResponse = await RequestToken(registration.ClientId!);
        Assert.False(tokenResponse.IsError, $"{tokenResponse.Error}: {tokenResponse.ErrorDescription}");
        Assert.Equal(Scope, tokenResponse.Scope);

        // Registration downloaded the CRL; the token request reused the cached copy.
        Assert.Equal(1, _crlHandler.DownloadCount);

        //
        // Revoke the client certificate: the CA publishes a new CRL at the same URL.
        //
        _crlHandler.Crl = BuildCrl(crlNumber: 2, DateTimeOffset.UtcNow.AddHours(1), revokeClient: true);

        // Wait until the cached CRL's nextUpdate has passed and its cache entry has expired.
        var wait = firstCrlNextUpdate - DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1);
        if (wait > TimeSpan.Zero)
        {
            _testOutputHelper.WriteLine($"Waiting {wait.TotalSeconds:F1}s for the cached CRL to expire");
            await Task.Delay(wait);
        }

        tokenResponse = await RequestToken(registration.ClientId!);

        Assert.True(tokenResponse.IsError, "a client whose certificate was revoked after registration got a token");
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Equal("Certificate chain validation failed", tokenResponse.ErrorDescription);
        Assert.Equal(2, _crlHandler.DownloadCount);
    }

    /// <summary>
    /// Evicting the cached CRL (for example when an operator learns of a revocation) makes the very
    /// next token request see the new CRL, without waiting for the cached one's nextUpdate.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_Token_Rejected_After_Revocation_When_Cached_Crl_Is_Evicted()
    {
        _crlHandler.Crl = BuildCrl(crlNumber: 1, DateTimeOffset.UtcNow.AddHours(1), revokeClient: false);

        var registration = await RegisterClientCredentialsClient();

        var tokenResponse = await RequestToken(registration.ClientId!);
        Assert.False(tokenResponse.IsError, $"{tokenResponse.Error}: {tokenResponse.ErrorDescription}");

        _crlHandler.Crl = BuildCrl(crlNumber: 2, DateTimeOffset.UtcNow.AddHours(1), revokeClient: true);

        // Until the cached CRL is evicted or expires, it is still the one used.
        tokenResponse = await RequestToken(registration.ClientId!);
        Assert.False(tokenResponse.IsError, $"{tokenResponse.Error}: {tokenResponse.ErrorDescription}");
        Assert.Equal(1, _crlHandler.DownloadCount);

        await _mockPipeline.Resolve<ICertificateDownloadCache>().RemoveCrlAsync(CrlUrl);

        tokenResponse = await RequestToken(registration.ClientId!);

        Assert.True(tokenResponse.IsError, "a client whose certificate was revoked after registration got a token");
        Assert.Equal("invalid_client", tokenResponse.Error);
        Assert.Equal("Certificate chain validation failed", tokenResponse.ErrorDescription);
        Assert.Equal(2, _crlHandler.DownloadCount);
    }

    private async Task<UdapDynamicClientRegistrationDocument> RegisterClientCredentialsClient()
    {
        var udapClient = _mockPipeline.Resolve<IUdapClient>();
        udapClient.UdapServerMetadata = new UdapMetadata(Substitute.For<UdapMetadataOptions>())
            { RegistrationEndpoint = UdapAuthServerPipeline.RegistrationEndpoint };

        var registration = await udapClient.RegisterClientCredentialsClient(_clientCert, Scope);
        Assert.Null(registration.GetError());
        Assert.NotNull(registration.ClientId);

        return registration;
    }

    private async Task<Duende.IdentityModel.Client.TokenResponse> RequestToken(string clientId)
    {
        var clientRequest = AccessTokenRequestForClientCredentialsBuilder.Create(
                clientId,
                IdentityServerPipeline.TokenEndpoint,
                _clientCert)
            .WithScope(Scope)
            .Build("RS384");

        return await _mockPipeline.BackChannelClient.UdapRequestClientCredentialsTokenAsync(clientRequest);
    }

    private byte[] BuildCrl(BigInteger crlNumber, DateTimeOffset nextUpdate, bool revokeClient)
    {
        var builder = new CertificateRevocationListBuilder();
        if (revokeClient)
        {
            builder.AddEntry(_clientCert, DateTimeOffset.UtcNow.AddSeconds(-1), X509RevocationReason.CessationOfOperation);
        }

        return builder.Build(
            _rootCert,
            crlNumber,
            nextUpdate,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1,
            DateTimeOffset.UtcNow.AddMinutes(-1));
    }

    private static X509Certificate2 CreateRootCa(RSA key)
    {
        var request = new CertificateRequest("CN=Revocation Test Root CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateClientCertificate(X509Certificate2 rootCert)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Revocation Test Client", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(rootCert, true, false));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUrl]));

        // The URI has a path, so SubjectAlternativeNameBuilder writes it verbatim (no trailing slash).
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri(ClientSan));
        request.CertificateExtensions.Add(san.Build());

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;

        using var issued = request.Create(
            rootCert,
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddMonths(6),
            serial);
        using var withKey = issued.CopyWithPrivateKey(key);

        // Round-trip through PKCS#12 so the private key is usable like one loaded from a file.
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx, "udap-test"), "udap-test", X509KeyStorageFlags.Exportable);
    }

    public void Dispose()
    {
        _clientCert.Dispose();
        _rootCert.Dispose();
        _rootKey.Dispose();
    }

    /// <summary>
    /// Serves the current CRL at <see cref="CrlUrl"/> and counts downloads.
    /// </summary>
    private sealed class CrlHttpHandler : HttpMessageHandler
    {
        private int _downloadCount;

        public byte[]? Crl { get; set; }

        public int DownloadCount => Volatile.Read(ref _downloadCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.ToString() != CrlUrl || Crl == null)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            Interlocked.Increment(ref _downloadCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Crl)
            });
        }
    }
}

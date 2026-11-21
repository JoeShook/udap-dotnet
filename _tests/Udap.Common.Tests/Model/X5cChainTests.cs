#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Udap.Common.Certificates;
using Udap.Common.Metadata;
using Udap.Model;
using Udap.Model.Access;
using Udap.Model.Registration;
using Udap.Model.Statement;

namespace Udap.Common.Tests.Model;

/// <summary>
/// The x5c header of UDAP JWTs carries the signing certificate followed by the intermediate that issued it.
/// </summary>
public class X5cChainTests
{
    private const string Password = "udap-test";
    private const string RsaClientPfx = "CertStore/issued/fhirlabs.net.client.pfx";
    private const string EcdsaClientPfx = "CertStore/issued/fhirlabs.net.ecdsa.client.pfx";
    private const string IntermediateSubject = "CN=SureFhir-Intermediate, OU=Intermediate, O=Fhir Coding, L=Portland, S=Oregon, C=US";

    [Fact]
    public void Build_OrdersLeafThenIssuingIntermediate_AndDropsRoot()
    {
        var (leaf, others) = LoadPfx(RsaClientPfx);

        // Root first, to show the order of the candidates does not matter.
        var chain = X5cChain.Build(leaf, others.OrderBy(c => X5cChain.IsSelfSigned(c) ? 0 : 1));

        Assert.Equal(2, chain.Count);
        Assert.Equal(leaf.Thumbprint, chain[0].Thumbprint);
        Assert.Equal(IntermediateSubject, chain[1].Subject);
        Assert.True(X5cChain.IncludesIssuingIntermediate(chain));
    }

    [Fact]
    public void Build_WithoutIntermediates_ReturnsLeafOnly()
    {
        var (leaf, others) = LoadPfx(RsaClientPfx);

        Assert.Single(X5cChain.Build(leaf, null));
        Assert.Single(X5cChain.Build(leaf, []));
        // Only the root: not an intermediate, so it is never placed in x5c.
        Assert.Single(X5cChain.Build(leaf, others.Where(X5cChain.IsSelfSigned)));
        Assert.False(X5cChain.IncludesIssuingIntermediate([leaf]));
    }

    [Fact]
    public void Build_IgnoresUnrelatedIntermediates()
    {
        var (leaf, _) = LoadPfx(RsaClientPfx);
        // An intermediate of another PKI (the untrusted client's issuer).
        var (_, untrustedChain) = LoadPfx("CertStore/issued/fhirlabs.net.untrusted.client.pfx");
        var unrelated = untrustedChain.Single(c => !X5cChain.IsSelfSigned(c));

        var chain = X5cChain.Build(leaf, untrustedChain);

        Assert.Single(chain);
        Assert.False(X5cChain.IncludesIssuingIntermediate([leaf, unrelated]));
    }

    [Theory]
    [InlineData(RsaClientPfx, UdapConstants.SupportedAlgorithm.RS256)]
    [InlineData(EcdsaClientPfx, UdapConstants.SupportedAlgorithm.ES384)]
    public void SignedSoftwareStatementBuilder_WithIntermediates_PutsIssuingIntermediateInX5c(string pfx, string algorithm)
    {
        var (leaf, others) = LoadPfx(pfx);

        var document = UdapDcrBuilderForClientCredentials
            .Create(leaf)
            .WithAudience("https://server/connect/register")
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .WithClientName("x5c test")
            .WithScope("system/Patient.rs")
            .Build();

        var jwt = SignedSoftwareStatementBuilder<UdapDynamicClientRegistrationDocument>
            .Create(leaf, others, document)
            .Build(algorithm);

        var x5c = ReadX5c(jwt);
        Assert.Equal(2, x5c.Count);
        Assert.Equal(leaf.Thumbprint, x5c[0].Thumbprint);
        Assert.Equal(IntermediateSubject, x5c[1].Subject);
    }

    [Fact]
    public void ExistingSingleCertificateBuilders_StillSendLeafOnly()
    {
        var (leaf, _) = LoadPfx(RsaClientPfx);

        var softwareStatement = UdapDcrBuilderForClientCredentials
            .Create(leaf)
            .WithAudience("https://server/connect/register")
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .BuildSoftwareStatement();

        Assert.Single(ReadX5c(softwareStatement));
    }

    [Fact]
    public async Task IssuedCertificateStore_CarriesIssuingIntermediate_IntoAllClientBuilders()
    {
        var store = CreateStore(RsaClientPfx, out _);
        await store.Resolve();

        var issued = Assert.Single(store.IssuedCertificates);
        var intermediate = Assert.Single(issued.Intermediates);
        Assert.Equal(IntermediateSubject, intermediate.Subject);

        var x5cCertificates = issued.GetX5cCertificates();
        Assert.Equal(2, x5cCertificates.Count);

        // Software statement
        var softwareStatement = UdapDcrBuilderForClientCredentials
            .Create(x5cCertificates)
            .WithAudience("https://server/connect/register")
            .WithExpiration(TimeSpan.FromMinutes(5))
            .WithJwtId()
            .BuildSoftwareStatement();
        AssertLeafThenIntermediate(softwareStatement, issued.Certificate);

        // Client assertion
        var tokenRequest = AccessTokenRequestForClientCredentialsBuilder
            .Create("client-id", "https://server/connect/token", x5cCertificates)
            .Build();
        AssertLeafThenIntermediate(tokenRequest.ClientAssertion.Value, issued.Certificate);

        // Certification
        var certification = UdapCertificationsAndEndorsementBuilder
            .Create("x5c certification", x5cCertificates)
            .WithExpiration(DateTime.UtcNow.AddMinutes(5))
            .BuildSoftwareStatement();
        AssertLeafThenIntermediate(certification, issued.Certificate);
    }

    [Fact]
    public async Task IssuedCertificateStore_LogsWarning_WhenIssuingIntermediateIsMissing()
    {
        var (leaf, _) = LoadPfx(RsaClientPfx);
        var leafOnlyPfx = Path.Combine(Path.GetTempPath(), $"x5c-leaf-only-{Guid.NewGuid():N}.pfx");
        await File.WriteAllBytesAsync(leafOnlyPfx, leaf.Export(X509ContentType.Pkcs12, Password));

        try
        {
            var store = CreateStore(leafOnlyPfx, out var logger);
            await store.Resolve();

            var issued = Assert.Single(store.IssuedCertificates);
            Assert.Empty(issued.Intermediates);
            Assert.Single(issued.GetX5cCertificates());
            Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("not available from the certificate store"));
        }
        finally
        {
            File.Delete(leafOnlyPfx);
        }
    }

    [Fact]
    public async Task IssuedCertificateStore_UsesCommunityIntermediates_WhenPfxHasOnlyTheLeaf()
    {
        var (leaf, _) = LoadPfx(RsaClientPfx);
        var leafOnlyPfx = Path.Combine(Path.GetTempPath(), $"x5c-leaf-only-{Guid.NewGuid():N}.pfx");
        await File.WriteAllBytesAsync(leafOnlyPfx, leaf.Export(X509ContentType.Pkcs12, Password));

        try
        {
            var store = CreateStore(leafOnlyPfx, out var logger, "CertStore/intermediates/SureFhirLabs_Intermediate.cer");
            await store.Resolve();

            var issued = Assert.Single(store.IssuedCertificates);
            Assert.Equal(IntermediateSubject, Assert.Single(issued.Intermediates).Subject);
            Assert.DoesNotContain(logger.Entries, e => e.Level == LogLevel.Warning);
        }
        finally
        {
            File.Delete(leafOnlyPfx);
        }
    }

    private static void AssertLeafThenIntermediate(string jwt, X509Certificate2 leaf)
    {
        var x5c = ReadX5c(jwt);
        Assert.Equal(2, x5c.Count);
        Assert.Equal(leaf.Thumbprint, x5c[0].Thumbprint);
        Assert.Equal(IntermediateSubject, x5c[1].Subject);
        Assert.True(X5cChain.IncludesIssuingIntermediate(x5c));
    }

    private static List<X509Certificate2> ReadX5c(string jwt)
    {
        var token = new JsonWebToken(jwt);
        Assert.True(token.TryGetHeaderValue<List<string>>("x5c", out var x5c));

#if NET9_0_OR_GREATER
        return x5c.Select(c => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(c))).ToList();
#else
        return x5c.Select(c => new X509Certificate2(Convert.FromBase64String(c))).ToList();
#endif
    }

    private static (X509Certificate2 Leaf, List<X509Certificate2> Others) LoadPfx(string path)
    {
#if NET9_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, Password, X509KeyStorageFlags.Exportable);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(path, Password, X509KeyStorageFlags.Exportable);
#endif
        var leaf = collection.Single(c => c.HasPrivateKey && !X5cChain.IsCertificateAuthority(c));

        return (leaf, collection.Where(c => c.Thumbprint != leaf.Thumbprint).ToList());
    }

    private static IssuedCertificateStore CreateStore(string pfxPath, out ListLogger<IssuedCertificateStore> logger, params string[] intermediates)
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities =
            [
                new Community
                {
                    Name = "udap://fhirlabs.net",
                    Intermediates = intermediates.ToList(),
                    IssuedCerts = [new IssuedCertFile { FilePath = pfxPath, Password = Password }]
                }
            ]
        };

        logger = new ListLogger<IssuedCertificateStore>();

        return new IssuedCertificateStore(new StaticOptionsMonitor<UdapFileCertStoreManifest>(manifest), logger);
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}

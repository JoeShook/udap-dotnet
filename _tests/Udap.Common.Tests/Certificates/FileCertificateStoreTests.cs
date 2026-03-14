#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Common.Certificates;
using Udap.Common.Metadata;

namespace Udap.Common.Tests.Certificates;

public class FileCertificateStoreTests
{
    private readonly IConfigurationRoot _configuration;

    public FileCertificateStoreTests()
    {
        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", false, true)
            .Build();
    }

    [Fact]
    public async Task Resolve_LoadsAnchorsAndIssuedCerts()
    {
        var manifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(manifest);

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());
        var result = await store.Resolve();

        Assert.NotEmpty(store.AnchorCertificates);
        Assert.NotEmpty(store.IssuedCertificates);
        Assert.Same(store, result);
    }

    [Fact]
    public async Task Resolve_CalledTwice_OnlyLoadsOnce()
    {
        var manifest = new UdapFileCertStoreManifest();
        _configuration.GetSection(Constants.UDAP_FILE_STORE_MANIFEST).Bind(manifest);

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());

        await store.Resolve();
        var anchorCount = store.AnchorCertificates.Count;
        var issuedCount = store.IssuedCertificates.Count;

        await store.Resolve();

        Assert.Equal(anchorCount, store.AnchorCertificates.Count);
        Assert.Equal(issuedCount, store.IssuedCertificates.Count);
    }

    [Fact]
    public async Task Resolve_EmptyManifest_NoExceptions()
    {
        var manifest = new UdapFileCertStoreManifest();

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());
        var result = await store.Resolve();

        Assert.Empty(store.AnchorCertificates);
        Assert.Empty(store.IssuedCertificates);
        Assert.Same(store, result);
    }

    [Fact]
    public async Task Resolve_MissingAnchorFilePath_ThrowsException()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    Anchors = new List<AnchoFile> { new AnchoFile { FilePath = null } }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());

        await Assert.ThrowsAsync<Exception>(() => store.Resolve());
    }

    [Fact]
    public async Task Resolve_NonExistentAnchorFile_ThrowsFileNotFoundException()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    Anchors = new List<AnchoFile>
                    {
                        new AnchoFile { FilePath = "nonexistent/path/cert.cer" }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());

        await Assert.ThrowsAsync<FileNotFoundException>(() => store.Resolve());
    }

    [Fact]
    public async Task Resolve_MissingIssuedCertFilePath_LogsWarning()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    IssuedCerts = new List<IssuedCertFile> { new IssuedCertFile { FilePath = null } }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var logger = Substitute.For<ILogger<FileCertificateStore>>();
        var store = new FileCertificateStore(monitor, logger);

        await store.Resolve();

        Assert.Empty(store.IssuedCertificates);
    }

    [Fact]
    public async Task Resolve_NonExistentIssuedCertFile_LogsWarningAndContinues()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    IssuedCerts = new List<IssuedCertFile>
                    {
                        new IssuedCertFile { FilePath = "nonexistent/path/cert.pfx", Password = "test" }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());

        await store.Resolve();

        Assert.Empty(store.IssuedCertificates);
    }

    [Fact]
    public async Task Resolve_WithIntermediates_LoadsIntermediatesIntoAnchor()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "udap://fhirlabs.net",
                    Intermediates = new List<string>
                    {
                        "CertStore/intermediates/SureFhirLabs_Intermediate.cer"
                    },
                    Anchors = new List<AnchoFile>
                    {
                        new AnchoFile { FilePath = "CertStore/anchors/SureFhirLabs_CA.cer" }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());
        await store.Resolve();

        Assert.Single(store.AnchorCertificates);
        var anchor = store.AnchorCertificates.First();
        Assert.NotNull(anchor.Intermediates);
        Assert.Single(anchor.Intermediates);
    }

    [Fact]
    public async Task Resolve_WithIssuedCertsFromConfig_LoadsCertificatesCorrectly()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "udap://fhirlabs.net",
                    Anchors = new List<AnchoFile>
                    {
                        new AnchoFile { FilePath = "CertStore/anchors/SureFhirLabs_CA.cer" }
                    },
                    IssuedCerts = new List<IssuedCertFile>
                    {
                        new IssuedCertFile
                        {
                            FilePath = "CertStore/issued/fhirlabs.net.client.pfx",
                            Password = "udap-test"
                        }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new FileCertificateStore(monitor, Substitute.For<ILogger<FileCertificateStore>>());
        await store.Resolve();

        Assert.Single(store.AnchorCertificates);
        Assert.NotEmpty(store.IssuedCertificates);
    }
}

using System.Security.Cryptography.X509Certificates;
using Udap.Util.Extensions;
using Xunit;

namespace Udap.Common.Tests.Util;

public class X509ExtensionTests
{
    private readonly string CertStore = "../../../../Udap.PKI.Generator/certstores";

    [Fact]
    public void ResolveUriSubjAltNameTest()
    {
        var certificate = new X509Certificate2($"{CertStore}/localhost_fhirlabs_community1/issued/fhirLabsApiClientLocalhostCert.cer");

        // Both should succeed.
        // The C# code cannot generated a SAN without the trailing slash on a URI without a path.
        // TODO: Need to consider issuing a PR to correct MS code base.  I think asp.net is the place.
        // But regardless I think Postels law applies here.
        Assert.Equal("https://localhost:5055/", certificate.ResolveUriSubjAltName("https://localhost:5055"));
        Assert.Equal("https://localhost:5055/", certificate.ResolveUriSubjAltName("https://localhost:5055/"));


        Assert.Equal("https://localhost:7016/fhir/r4", certificate.ResolveUriSubjAltName("https://localhost:7016/fhir/r4"));
        Assert.Equal("https://localhost:7016/fhir/r4", certificate.ResolveUriSubjAltName("https://localhost:7016/fhir/r4/"));
    }

    [Fact]
    public void KeyUsageTest()
    {
        var certificate = new X509Certificate2($"CertStore/anchors/SureFhirLabs_CA.cer");

        var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
        Assert.NotEmpty(extensions);

        var keyUsageStrings = extensions.Single().KeyUsages.ToKeyUsageToString().ToList();
        var crlSignIndex = keyUsageStrings.IndexOf("CrlSign");
        var keyCertSignIndex = keyUsageStrings.IndexOf("KeyCertSign");
        Assert.True(crlSignIndex >= 0, "Expected 'CrlSign' in key usage list");
        Assert.True(keyCertSignIndex >= 0, "Expected 'KeyCertSign' in key usage list");
        Assert.True(crlSignIndex < keyCertSignIndex, "Expected 'CrlSign' before 'KeyCertSign'");
    }

    [Fact]
    public void GetSubjectAltNames()
    {
        var certificate = new X509Certificate2($"{CertStore}/SurefhirCertificationLabs_Community/issued/FhirLabsAdminCertification.cer");

        var subjectAltNames = certificate.GetSubjectAltNames();
        Assert.Empty(subjectAltNames);
    }
}

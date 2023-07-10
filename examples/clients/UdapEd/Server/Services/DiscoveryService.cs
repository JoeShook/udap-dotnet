#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Udap.Client.Client;
using Udap.Client.Internal;
using Udap.Common.Certificates;
using Udap.Common.Extensions;
using Udap.Common.Models;
using Udap.Model;
using Udap.Util.Extensions;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace UdapEd.Server.Services;

public class DiscoveryService
{
    private readonly IUdapClient _udapClient;
    readonly HttpClient _httpClient;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<DiscoveryService> _logger;

    public DiscoveryService(IUdapClient udapClient, HttpClient httpClient, IHttpContextAccessor httpContextAccessor, ILogger<DiscoveryService> logger)
    {
        _udapClient = udapClient;
        _httpClient = httpClient;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<MetadataVerificationModel?> GetMetadataVerificationModel(string metadataUrl, string? community, CancellationToken token)
    {
        try
        {
            var loadedStatus = AnchorCertificateLoadStatus();

            if (loadedStatus != null && (loadedStatus.CertLoaded == CertLoadedEnum.Positive))
            {
                return await GetMetadata(metadataUrl, community);
            }

            return await GetUnvalidatedMetadata(metadataUrl, community);

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed GetMetadataVerificationModel");
            return null;
        }
    }

    public CertificateStatusViewModel UploadAnchorCertificate(string base64String)
    {
        var result = new CertificateStatusViewModel { CertLoaded = CertLoadedEnum.Negative };

        try
        {
            var certBytes = Convert.FromBase64String(base64String);
            var certificate = new X509Certificate2(certBytes);
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;
            _httpContextAccessor.HttpContext?.Session.SetString(UdapEdConstants.ANCHOR_CERTIFICATE, base64String);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                $"Failed loading certificate from {nameof(base64String)} {base64String}");

            return result;
        }
    }

    public async Task<CertificateStatusViewModel?> LoadUdapOrgAnchor()
    {
        var result = new CertificateStatusViewModel { CertLoaded = CertLoadedEnum.Negative };
        var anchorCertificate = "http://certs.emrdirect.com/certs/EMRDirectTestCA.crt";
        try
        {
            var response = await _httpClient.GetAsync(new Uri(anchorCertificate));
            response.EnsureSuccessStatusCode();
            var certBytes = await response.Content.ReadAsByteArrayAsync();
            var certificate = new X509Certificate2(certBytes);
            result.DistinguishedName = certificate.SubjectName.Name;
            result.Thumbprint = certificate.Thumbprint;
            result.CertLoaded = CertLoadedEnum.Positive;
            _httpContextAccessor.HttpContext?.Session.SetString(UdapEdConstants.ANCHOR_CERTIFICATE, Convert.ToBase64String(certBytes));

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                $"Failed loading certificate from {nameof(anchorCertificate)} {anchorCertificate}");

            return result;
        }
    }

    public CertificateStatusViewModel? AnchorCertificateLoadStatus()
    {
        var result = new CertificateStatusViewModel
        {
            CertLoaded = CertLoadedEnum.Negative
        };

        try
        {
            var base64String = _httpContextAccessor.HttpContext?.Session.GetString(UdapEdConstants.ANCHOR_CERTIFICATE);

            if (base64String != null)
            {
                var certBytes = Convert.FromBase64String(base64String);
                var certificate = new X509Certificate2(certBytes);
                result.DistinguishedName = certificate.SubjectName.Name;
                result.Thumbprint = certificate.Thumbprint;
                result.CertLoaded = CertLoadedEnum.Positive;
            }
            else
            {
                result.CertLoaded = CertLoadedEnum.Negative;
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex.Message);

            return result;
        }
    }

    public void SetBaseFhirUrl(string baseFhirUrl, bool resetToken = false)
    {
        _httpContextAccessor.HttpContext?.Session.SetString(UdapEdConstants.BASE_URL, baseFhirUrl);

        if (resetToken)
        {
            _httpContextAccessor.HttpContext?.Session.Remove(UdapEdConstants.TOKEN);
        }
    }

    public CertificateViewModel GetCertificateData(IEnumerable<string> base64EncodedCertificate)
    {
        try
        {
            var certBytes = Convert.FromBase64String(base64EncodedCertificate.First());
            var cert = new X509Certificate2(certBytes);
            var result = BuildCertificateDisplayData(cert);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed GetCertificateData from list");
            return null;
        }
    }

    public CertificateViewModel GetCertificateData(string base64EncodedCertificate)
    {
        try
        {
            var certBytes = Convert.FromBase64String(base64EncodedCertificate);
            var cert = new X509Certificate2(certBytes);
            var result = BuildCertificateDisplayData(cert);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed GetCertificateData");
            return null;
        }
    }


    private async Task<MetadataVerificationModel?> GetMetadata(string metadataUrl, string? community)
    {
        var baseUrl = metadataUrl.EnsureTrailingSlash() + UdapConstants.Discovery.DiscoveryEndpoint;
        var anchorString = _httpContextAccessor.HttpContext?.Session.GetString(UdapEdConstants.ANCHOR_CERTIFICATE);

        if (anchorString != null)
        {
            var model = new MetadataVerificationModel();

            var certBytes = Convert.FromBase64String(anchorString);
            var anchorCert = new X509Certificate2(certBytes);
            var trustAnchorStore = new TrustAnchorMemoryStore()
            {
                AnchorCertificates = new HashSet<Anchor>
                {
                    new Anchor(anchorCert)
                }
            };


            _udapClient.Problem += element =>
                model.Notifications.Add(element.ChainElementStatus.Summarize(TrustChainValidator.DefaultProblemFlags));
            _udapClient.Untrusted += certificate2 => model.Notifications.Add("Untrusted: " + certificate2.Subject);
            _udapClient.TokenError += message => model.Notifications.Add("TokenError: " + message);

            await _udapClient.ValidateResource(
                baseUrl.GetBaseUrlFromMetadataUrl(),
                trustAnchorStore,
                community);

            model.UdapServerMetaData = _udapClient.UdapServerMetaData;
            _httpContextAccessor.HttpContext?.Session.SetString(UdapEdConstants.BASE_URL, baseUrl.GetBaseUrlFromMetadataUrl());

            return model;
        }

        return null;
    }

    private async Task<MetadataVerificationModel?> GetUnvalidatedMetadata(string metadataUrl, string? community)
    {
        var baseUrl = metadataUrl.EnsureTrailingSlash() + UdapConstants.Discovery.DiscoveryEndpoint;
        if (!string.IsNullOrEmpty(community))
        {
            baseUrl += $"?{UdapConstants.Community}={community}";
        }

        _logger.LogDebug(baseUrl);
        var response = await _httpClient.GetStringAsync(baseUrl);
        var result = JsonSerializer.Deserialize<UdapMetadata>(response);
        _httpContextAccessor.HttpContext?.Session.SetString(UdapEdConstants.BASE_URL, baseUrl.GetBaseUrlFromMetadataUrl());

        var model = new MetadataVerificationModel
        {
            UdapServerMetaData = result,
            Notifications = new List<string>
            {
                "No anchor loaded.  Un-Validated resource server."
            }
        };

        return model;
    }

    private CertificateViewModel BuildCertificateDisplayData(X509Certificate2 cert)
    {
        var data = new Dictionary<string, string>();

        data.Add("Serial Number", cert.SerialNumber);
        data.Add("Subject", cert.Subject);
        data.Add("Subject Alternative Names", GetSANs(cert));
        data.Add("Public Key Alogorithm", GetPublicKeyAlgorithm(cert));
        data.Add("Certificate Policy", BuildPolicyInfo(cert));
        data.Add("Start Date", cert.GetEffectiveDateString());
        data.Add("End Date", cert.GetExpirationDateString());
        data.Add("Key Usage", GetKeyUsage(cert));
        // data.Add("Extended Key Usage", GetExtendedKeyUsage(cert));
        data.Add("Issuer", cert.Issuer);
        data.Add("Subject Key Identifier", GetSubjectKeyIdentifier(cert));
        data.Add("Authority Key Identifier", GetAuthorityKeyIdentifier(cert));
        data.Add("Authority Information Access", GetAIAUrls(cert));
        data.Add("CRL Distribution", GetCrlDistributionPoint(cert));
        data.Add("Thumbprint SHA1", cert.Thumbprint);

        var result = new CertificateViewModel();

        result.TableDisplay.Add(data);
        return result;
    }

    private string GetAIAUrls(X509Certificate2 cert)
    {
        var aiaExtensions =
            cert.Extensions["1.3.6.1.5.5.7.1.1"] as X509AuthorityInformationAccessExtension;

        if (aiaExtensions == null)
        {
            return string.Empty;
        }
        var sb = new StringBuilder();
        foreach (var url in aiaExtensions!.EnumerateCAIssuersUris())
        {
            sb.AppendLine(url);
        }

        return sb.ToString();
    }

    private string GetPublicKeyAlgorithm(X509Certificate2 cert)
    {
        string keyAlgOid = cert.GetKeyAlgorithm();
        var oid = new Oid(keyAlgOid);

        var key = cert.GetRSAPublicKey() as AsymmetricAlgorithm ?? cert.GetECDsaPublicKey();
        return $"{oid.FriendlyName} ({key?.KeySize})";
    }

    private string GetSANs(X509Certificate2 cert)
    {
        var sans = cert.GetSubjectAltNames();

        if (!sans.Any())
        {
            return string.Empty;
        }

        var sb = new StringBuilder();

        foreach (var tuple in sans)
        {
            sb.AppendLine($"{tuple.Item1} : {tuple.Item2}");
        }

        return sb.ToString();
    }

    private string BuildPolicyInfo(X509Certificate2 cert)
    {
        var extension = cert.GetExtensionValue("2.5.29.32") as Asn1OctetString;
        if (extension == null)
        {
            return string.Empty;
        }
        var policies = extension.GetOctets();
        var policyInfoList = CertificatePolicies.GetInstance(policies).GetPolicyInformation();
        return string.Join("\r\n", policyInfoList.Select(p => p.PolicyIdentifier.ToString()));
    }

    private string GetKeyUsage(X509Certificate2 cert)
    {
        var extensions = cert.Extensions.OfType<X509KeyUsageExtension>().ToList();

        if (!extensions.Any())
        {
            return String.Empty;
        }

        var keyUsage = extensions.First().KeyUsages;

        return string.Join("; ", keyUsage.ToKeyUsageToString());
    }

    private string GetExtendedKeyUsage(X509Certificate2 cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage.Id) as Asn1OctetString;

        if (ext == null)
        {
            return string.Empty;
        }

        var instance = ExtendedKeyUsage.GetInstance(Asn1Object.FromByteArray(ext.GetOctets()));

        var joe = instance.GetAllUsages();
        return joe.ToString();
    }

    private string GetSubjectKeyIdentifier(X509Certificate2 cert)
    {
        var extensions = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().ToList();

        if (!extensions.Any())
        {
            return string.Empty;
        }

        return extensions.First().SubjectKeyIdentifier ?? string.Empty;
    }

    private string GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        var extensions = cert.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().ToList();

        if (!extensions.Any())
        {
            return string.Empty;
        }

        var bytes = extensions.First().KeyIdentifier?.ToArray();

        if (bytes == null)
        {
            return string.Empty;
        }

        return CreateByteStringRep(bytes);
    }

    private string GetCrlDistributionPoint(X509Certificate2 cert)
    {
        var ext = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints.Id);

        if (ext == null)
        {
            return string.Empty;
        }

        var distPoints = CrlDistPoint.GetInstance(ext);
        var retVal = new List<string>();

        foreach (var distPoint in distPoints.GetDistributionPoints())
        {
            if (distPoint.DistributionPointName != null
                && distPoint.DistributionPointName.PointType == DistributionPointName.FullName)
            {
                var names = GeneralNames.GetInstance(distPoint.DistributionPointName.Name);

                foreach (var generalName in names.GetNames())
                {
                    var name = generalName.Name.ToString();
                    if (name != null)
                    {
                        retVal.Add(name);
                    }
                }
            }
        }

        return string.Join("\r\n", retVal);
    }

    private static string CreateByteStringRep(byte[] bytes)
    {
        var c = new char[bytes.Length * 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i] >> 4;
            c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
            b = bytes[i] & 0xF;
            c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
        }
        return new string(c);

    }
}
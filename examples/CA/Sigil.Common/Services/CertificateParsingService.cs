using System.Security.Cryptography.X509Certificates;

namespace Sigil.Common.Services;

public enum DetectedCertRole
{
    RootCa,
    IntermediateCa,
    EndEntity
}

public class ParsedCertificate
{
    public X509Certificate2 Certificate { get; set; } = null!;
    public byte[] RawFileBytes { get; set; } = [];
    public string FileName { get; set; } = string.Empty;
    public DetectedCertRole DetectedRole { get; set; }
    public string? SubjectKeyIdentifier { get; set; }
    public string? AuthorityKeyIdentifier { get; set; }
    public string? SubjectAltNames { get; set; }
    public string Algorithm { get; set; } = "Unknown";
    public int KeySize { get; set; }
    public bool HasPrivateKey { get; set; }
}

public class CertificateParsingService
{
    /// <summary>
    /// Parses a certificate file (.pfx, .cer, .pem) and returns structured info.
    /// </summary>
    public ParsedCertificate? Parse(byte[] fileBytes, string fileName, string? password = null)
    {
        X509Certificate2? cert = null;
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        try
        {
            if (ext == ".pfx" || ext == ".p12")
            {
                cert = X509CertificateLoader.LoadPkcs12(fileBytes, password,
                    X509KeyStorageFlags.Exportable);
            }
            else if (ext is ".cer" or ".crt" or ".der")
            {
                cert = X509CertificateLoader.LoadCertificate(fileBytes);
            }
            else if (ext == ".pem")
            {
                cert = X509CertificateLoader.LoadCertificate(fileBytes);
            }
            else
            {
                // Try PEM first, then DER
                try
                {
                    cert = X509CertificateLoader.LoadCertificate(fileBytes);
                }
                catch
                {
                    cert = X509CertificateLoader.LoadPkcs12(fileBytes, password,
                        X509KeyStorageFlags.Exportable);
                }
            }
        }
        catch
        {
            return null;
        }

        if (cert == null) return null;

        var (algorithm, keySize) = GetKeyInfo(cert);

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = fileBytes,
            FileName = fileName,
            DetectedRole = DetectRole(cert),
            SubjectKeyIdentifier = GetSubjectKeyIdentifier(cert),
            AuthorityKeyIdentifier = GetAuthorityKeyIdentifier(cert),
            SubjectAltNames = GetSubjectAltNames(cert),
            Algorithm = algorithm,
            KeySize = keySize,
            HasPrivateKey = cert.HasPrivateKey
        };
    }

    private static DetectedCertRole DetectRole(X509Certificate2 cert)
    {
        var bcExt = cert.Extensions["2.5.29.19"]; // BasicConstraints
        if (bcExt != null)
        {
            var bc = new X509BasicConstraintsExtension(bcExt, bcExt.Critical);
            if (bc.CertificateAuthority)
            {
                // Self-signed = root, otherwise intermediate
                return cert.Subject == cert.Issuer
                    ? DetectedCertRole.RootCa
                    : DetectedCertRole.IntermediateCa;
            }
        }

        return DetectedCertRole.EndEntity;
    }

    private static string? GetSubjectKeyIdentifier(X509Certificate2 cert)
    {
        var skiExt = cert.Extensions["2.5.29.14"];
        if (skiExt == null) return null;
        var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
        return ski.SubjectKeyIdentifier;
    }

    private static string? GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        var akiExt = cert.Extensions["2.5.29.35"];
        if (akiExt?.RawData == null || akiExt.RawData.Length < 6) return null;

        try
        {
            var data = akiExt.RawData;
            int offset = 2; // skip SEQUENCE tag + length
            if (data[offset] == 0x80) // [0] implicit tag
            {
                var len = data[offset + 1];
                var keyId = new byte[len];
                Array.Copy(data, offset + 2, keyId, 0, len);
                return Convert.ToHexString(keyId);
            }
        }
        catch { }

        return null;
    }

    private static string? GetSubjectAltNames(X509Certificate2 cert)
    {
        var sanExt = cert.Extensions["2.5.29.17"];
        if (sanExt == null) return null;

        try
        {
            var formatted = sanExt.Format(multiLine: true);
            var lines = formatted.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return string.Join("; ", lines);
        }
        catch
        {
            return null;
        }
    }

    private static (string algorithm, int keySize) GetKeyInfo(X509Certificate2 cert)
    {
        var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return ("RSA", rsa.KeySize);

        var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null) return ("ECDSA", ecdsa.KeySize);

        return ("Unknown", 0);
    }
}

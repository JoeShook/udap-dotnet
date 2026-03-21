namespace Udap.Common;

/// <summary>
/// Standard PEM header/footer label constants for encoding and decoding
/// cryptographic keys and certificates.
/// </summary>
public static class PemLabels
{
    /// <summary>PKCS#8 unencrypted private key (<c>PRIVATE KEY</c>).</summary>
    public const string Pkcs8PrivateKey = "PRIVATE KEY";

    /// <summary>PKCS#8 encrypted private key (<c>ENCRYPTED PRIVATE KEY</c>).</summary>
    public const string EncryptedPkcs8PrivateKey = "ENCRYPTED PRIVATE KEY";

    /// <summary>Subject Public Key Info (<c>PUBLIC KEY</c>).</summary>
    public const string SpkiPublicKey = "PUBLIC KEY";

    /// <summary>RSA public key in PKCS#1 format (<c>RSA PUBLIC KEY</c>).</summary>
    public const string RsaPublicKey = "RSA PUBLIC KEY";

    /// <summary>RSA private key in PKCS#1 format (<c>RSA PRIVATE KEY</c>).</summary>
    public const string RsaPrivateKey = "RSA PRIVATE KEY";

    /// <summary>Elliptic Curve private key in SEC 1 format (<c>EC PRIVATE KEY</c>).</summary>
    public const string EcPrivateKey = "EC PRIVATE KEY";

    /// <summary>X.509 certificate (<c>CERTIFICATE</c>).</summary>
    public const string X509Certificate = "CERTIFICATE";

    /// <summary>PKCS#7 certificate bundle (<c>PKCS7</c>).</summary>
    public const string Pkcs7Certificate = "PKCS7";
}

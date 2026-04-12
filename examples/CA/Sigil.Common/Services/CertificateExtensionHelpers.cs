#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sigil.Common.Services;

/// <summary>
/// Static helpers for building X.509 certificate extensions that .NET doesn't natively support.
/// Extracted from Udap.PKI.Generator for reuse by Sigil and CLI tools.
/// </summary>
public static class CertificateExtensionHelpers
{
    /// <summary>
    /// Adds an Authority Key Identifier (AKI) extension (OID 2.5.29.35)
    /// derived from the issuing CA's Subject Key Identifier.
    /// </summary>
    public static void AddAuthorityKeyIdentifier(
        X509Certificate2 issuerCert,
        CertificateRequest request)
    {
        var issuerSubjectKey = issuerCert.Extensions["2.5.29.14"]?.RawData;
        if (issuerSubjectKey == null || issuerSubjectKey.Length < 4)
            return;

        var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
        var authorityKeyIdentifier = new byte[segment.Count + 4];
        authorityKeyIdentifier[0] = 0x30; // SEQUENCE
        authorityKeyIdentifier[1] = 0x16;
        authorityKeyIdentifier[2] = 0x80; // [0] implicit KeyIdentifier
        authorityKeyIdentifier[3] = 0x14;
        segment.CopyTo(authorityKeyIdentifier, 4);

        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
    }

    /// <summary>
    /// Adds an Authority Key Identifier extension to a list of extensions (for remote signing path).
    /// </summary>
    public static void AddAuthorityKeyIdentifierToList(
        X509Certificate2 issuerCert,
        List<X509Extension> extensions)
    {
        var issuerSubjectKey = issuerCert.Extensions["2.5.29.14"]?.RawData;
        if (issuerSubjectKey == null || issuerSubjectKey.Length < 4)
            return;

        var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
        var authorityKeyIdentifier = new byte[segment.Count + 4];
        authorityKeyIdentifier[0] = 0x30; // SEQUENCE
        authorityKeyIdentifier[1] = 0x16;
        authorityKeyIdentifier[2] = 0x80; // [0] implicit KeyIdentifier
        authorityKeyIdentifier[3] = 0x14;
        segment.CopyTo(authorityKeyIdentifier, 4);

        extensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
    }

    /// <summary>
    /// Builds a CRL Distribution Points extension (OID 2.5.29.31) for a single HTTP URL.
    /// Supports URLs up to 119 characters.
    /// </summary>
    public static X509Extension MakeCdp(string url)
    {
        byte[] encodedUrl = Encoding.ASCII.GetBytes(url);

        if (encodedUrl.Length > 119)
        {
            throw new ArgumentException(
                $"CDP URL must be 119 characters or fewer (got {encodedUrl.Length}). " +
                "Use BouncyCastle for longer URLs.", nameof(url));
        }

        byte[] payload = new byte[encodedUrl.Length + 10];
        int offset = 0;
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 8);
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 6);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 4);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 2);
        payload[offset++] = 0x86;
        payload[offset++] = (byte)encodedUrl.Length;
        Buffer.BlockCopy(encodedUrl, 0, payload, offset, encodedUrl.Length);

        return new X509Extension("2.5.29.31", payload, critical: false);
    }

    /// <summary>
    /// Builds an Authority Information Access (AIA) extension (OID 1.3.6.1.5.5.7.1.1)
    /// with a CA Issuers access method pointing to the given URI.
    /// </summary>
    public static X509Extension BuildAiaExtension(Uri caIssuerUri, bool critical = false)
    {
        var encodedParts = new List<byte[]>();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2"); // CA Issuers
        encodedParts.Add(writer.Encode());

        writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(
            UniversalTagNumber.IA5String,
            caIssuerUri.AbsoluteUri,
            new Asn1Tag(TagClass.ContextSpecific, 6));
        encodedParts.Add(writer.Encode());

        writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (byte[] part in encodedParts)
            {
                writer.WriteEncodedValue(part);
            }
        }

        var sequenceBytes = writer.Encode();

        writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(sequenceBytes);
        }

        return new X509Extension("1.3.6.1.5.5.7.1.1", writer.Encode(), critical);
    }
}

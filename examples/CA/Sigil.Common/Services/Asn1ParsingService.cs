using System.Text;
using Org.BouncyCastle.Asn1;

namespace Sigil.Common.Services;

public class Asn1Node
{
    public string TagName { get; set; } = string.Empty;
    public string TagClass { get; set; } = string.Empty;
    public int TagNumber { get; set; }
    public int Offset { get; set; }
    public int Length { get; set; }
    public string? Value { get; set; }
    public string? FriendlyName { get; set; }
    public bool IsConstructed { get; set; }
    public List<Asn1Node> Children { get; set; } = new();
}

public class Asn1ParsingService
{
    private static readonly Dictionary<string, string> WellKnownOids = new()
    {
        // X.500 DN attributes
        ["2.5.4.3"] = "commonName",
        ["2.5.4.5"] = "serialNumber",
        ["2.5.4.6"] = "countryName",
        ["2.5.4.7"] = "localityName",
        ["2.5.4.8"] = "stateOrProvinceName",
        ["2.5.4.10"] = "organizationName",
        ["2.5.4.11"] = "organizationalUnitName",

        // X.509 extensions
        ["2.5.29.14"] = "subjectKeyIdentifier",
        ["2.5.29.15"] = "keyUsage",
        ["2.5.29.17"] = "subjectAltName",
        ["2.5.29.19"] = "basicConstraints",
        ["2.5.29.20"] = "cRLNumber",
        ["2.5.29.31"] = "cRLDistributionPoints",
        ["2.5.29.32"] = "certificatePolicies",
        ["2.5.29.35"] = "authorityKeyIdentifier",
        ["2.5.29.37"] = "extKeyUsage",

        // Extended key usage
        ["1.3.6.1.5.5.7.3.1"] = "serverAuth",
        ["1.3.6.1.5.5.7.3.2"] = "clientAuth",
        ["1.3.6.1.5.5.7.3.3"] = "codeSigning",
        ["1.3.6.1.5.5.7.3.4"] = "emailProtection",
        ["1.3.6.1.5.5.7.3.8"] = "timeStamping",

        // Authority info access
        ["1.3.6.1.5.5.7.1.1"] = "authorityInfoAccess",
        ["1.3.6.1.5.5.7.48.1"] = "ocsp",
        ["1.3.6.1.5.5.7.48.2"] = "caIssuers",

        // Signature algorithms
        ["1.2.840.113549.1.1.1"] = "rsaEncryption",
        ["1.2.840.113549.1.1.5"] = "sha1WithRSAEncryption",
        ["1.2.840.113549.1.1.11"] = "sha256WithRSAEncryption",
        ["1.2.840.113549.1.1.12"] = "sha384WithRSAEncryption",
        ["1.2.840.113549.1.1.13"] = "sha512WithRSAEncryption",
        ["1.2.840.10045.2.1"] = "ecPublicKey",
        ["1.2.840.10045.4.3.2"] = "ecdsaWithSHA256",
        ["1.2.840.10045.4.3.3"] = "ecdsaWithSHA384",
        ["1.2.840.10045.4.3.4"] = "ecdsaWithSHA512",

        // Elliptic curves
        ["1.2.840.10045.3.1.7"] = "prime256v1 (P-256)",
        ["1.3.132.0.34"] = "secp384r1 (P-384)",
        ["1.3.132.0.35"] = "secp521r1 (P-521)",
    };

    public Asn1Node? Parse(byte[] derBytes)
    {
        try
        {
            using var stream = new MemoryStream(derBytes);
            var asn1Stream = new Asn1InputStream(stream);
            var obj = asn1Stream.ReadObject();
            if (obj == null) return null;

            return BuildNode(obj, 0);
        }
        catch
        {
            return null;
        }
    }

    public Asn1Node? ParsePem(string pem)
    {
        try
        {
            // Extract DER from PEM
            var lines = pem.Split('\n')
                .Select(l => l.Trim())
                .Where(l => !l.StartsWith("-----"))
                .ToList();
            var base64 = string.Join("", lines);
            var derBytes = Convert.FromBase64String(base64);
            return Parse(derBytes);
        }
        catch
        {
            return null;
        }
    }

    private Asn1Node BuildNode(Asn1Object obj, int depth)
    {
        var node = new Asn1Node
        {
            TagName = GetTagName(obj),
            TagClass = GetTagClass(obj),
            TagNumber = GetTagNumber(obj),
            IsConstructed = obj is Asn1Sequence or Asn1Set or Asn1TaggedObject
        };

        switch (obj)
        {
            case Asn1Sequence seq:
                foreach (var child in seq)
                {
                    if (child is Asn1Object childObj)
                        node.Children.Add(BuildNode(childObj, depth + 1));
                    else if (child is Asn1Encodable encodable)
                        node.Children.Add(BuildNode(encodable.ToAsn1Object(), depth + 1));
                }
                break;

            case Asn1Set set:
                foreach (var child in set)
                {
                    if (child is Asn1Object childObj)
                        node.Children.Add(BuildNode(childObj, depth + 1));
                    else if (child is Asn1Encodable encodable)
                        node.Children.Add(BuildNode(encodable.ToAsn1Object(), depth + 1));
                }
                break;

            case Asn1TaggedObject tagged:
                node.TagName = $"[{tagged.TagNo}]";
                node.TagNumber = tagged.TagNo;
                node.IsConstructed = true;
                try
                {
                    var baseObj = tagged.GetBaseObject().ToAsn1Object();
                    node.Children.Add(BuildNode(baseObj, depth + 1));
                }
                catch
                {
                    node.Value = FormatHex(tagged.GetEncoded());
                    node.IsConstructed = false;
                }
                break;

            case DerObjectIdentifier oid:
                node.Value = oid.Id;
                if (WellKnownOids.TryGetValue(oid.Id, out var friendly))
                    node.FriendlyName = friendly;
                break;

            case DerInteger integer:
                var bigInt = integer.Value;
                node.Value = bigInt.BitLength > 64
                    ? FormatHex(bigInt.ToByteArrayUnsigned(), 32)
                    : bigInt.ToString();
                break;

            case DerBitString bitString:
                node.Value = FormatHex(bitString.GetBytes(), 32);
                node.Length = bitString.GetBytes().Length;
                break;

            case DerOctetString octetString:
                // Try to parse as nested ASN.1
                try
                {
                    var nested = new Asn1InputStream(octetString.GetOctets()).ReadObject();
                    if (nested is Asn1Sequence or Asn1TaggedObject)
                    {
                        node.IsConstructed = true;
                        node.Children.Add(BuildNode(nested, depth + 1));
                    }
                    else
                    {
                        node.Value = FormatHex(octetString.GetOctets(), 32);
                    }
                }
                catch
                {
                    node.Value = FormatHex(octetString.GetOctets(), 32);
                }
                node.Length = octetString.GetOctets().Length;
                break;

            case DerUtf8String utf8:
                node.Value = utf8.GetString();
                break;

            case DerPrintableString printable:
                node.Value = printable.GetString();
                break;

            case DerIA5String ia5:
                node.Value = ia5.GetString();
                break;

            case DerVisibleString visible:
                node.Value = visible.GetString();
                break;

            case DerBmpString bmp:
                node.Value = bmp.GetString();
                break;

            case DerGeneralizedTime genTime:
                node.Value = genTime.ToDateTime().ToString("yyyy-MM-dd HH:mm:ss UTC");
                break;

            case DerUtcTime utcTime:
                node.Value = utcTime.ToDateTime().ToString("yyyy-MM-dd HH:mm:ss UTC");
                break;

            case DerBoolean boolean:
                node.Value = boolean.IsTrue ? "TRUE" : "FALSE";
                break;

            case DerNull:
                node.Value = "NULL";
                break;

            case DerEnumerated enumerated:
                node.Value = enumerated.Value.ToString();
                break;

            default:
                try
                {
                    node.Value = FormatHex(obj.GetEncoded(), 32);
                }
                catch
                {
                    node.Value = obj.ToString();
                }
                break;
        }

        return node;
    }

    private static string GetTagName(Asn1Object obj) => obj switch
    {
        Asn1Sequence => "SEQUENCE",
        Asn1Set => "SET",
        DerObjectIdentifier => "OID",
        DerInteger => "INTEGER",
        DerBitString => "BIT STRING",
        DerOctetString => "OCTET STRING",
        DerUtf8String => "UTF8String",
        DerPrintableString => "PrintableString",
        DerIA5String => "IA5String",
        DerVisibleString => "VisibleString",
        DerBmpString => "BMPString",
        DerGeneralizedTime => "GeneralizedTime",
        DerUtcTime => "UTCTime",
        DerBoolean => "BOOLEAN",
        DerNull => "NULL",
        DerEnumerated => "ENUMERATED",
        Asn1TaggedObject tagged => $"[{tagged.TagNo}]",
        _ => obj.GetType().Name
    };

    private static string GetTagClass(Asn1Object obj) => obj switch
    {
        Asn1TaggedObject => "CONTEXT",
        _ => "UNIVERSAL"
    };

    private static int GetTagNumber(Asn1Object obj) => obj switch
    {
        Asn1Sequence => 0x10,
        Asn1Set => 0x11,
        DerObjectIdentifier => 0x06,
        DerInteger => 0x02,
        DerBitString => 0x03,
        DerOctetString => 0x04,
        DerUtf8String => 0x0C,
        DerPrintableString => 0x13,
        DerIA5String => 0x16,
        DerUtcTime => 0x17,
        DerGeneralizedTime => 0x18,
        DerBoolean => 0x01,
        DerNull => 0x05,
        Asn1TaggedObject tagged => tagged.TagNo,
        _ => -1
    };

    private static string FormatHex(byte[] bytes, int maxBytes = 0)
    {
        if (bytes.Length == 0) return "(empty)";

        var hex = Convert.ToHexString(bytes);

        // Insert spaces every 2 chars for readability
        var sb = new StringBuilder();
        for (int i = 0; i < hex.Length; i += 2)
        {
            if (maxBytes > 0 && i / 2 >= maxBytes)
            {
                sb.Append($"... ({bytes.Length} bytes)");
                break;
            }
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(hex, i, Math.Min(2, hex.Length - i));
        }

        return sb.ToString();
    }
}

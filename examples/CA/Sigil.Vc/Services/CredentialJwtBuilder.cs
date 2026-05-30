#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;

namespace Sigil.Vc.Services;

/// <summary>
/// Assembles a compact JWT-VC: base64url(header).base64url(payload).base64url(signature).
/// Signs via <see cref="ISigningProvider"/> so the issuer key may live in any backing store
/// the provider supports (local for Phase A; Vault/KMS later).
/// </summary>
public static class CredentialJwtBuilder
{
    public static async Task<string> BuildAsync(
        VerificationMethod issuerKey,
        JsonObject header,
        JsonObject payload,
        ISigningProvider signing,
        CancellationToken ct = default)
    {
        var headerSegment = Base64Url(Serialize(header));
        var payloadSegment = Base64Url(Serialize(payload));
        var signingInput = $"{headerSegment}.{payloadSegment}";

        var signingInputBytes = Encoding.ASCII.GetBytes(signingInput);
        var keyRef = new SigningKeyReference(
            Provider: issuerKey.Provider,
            KeyIdentifier: issuerKey.KeyIdentifier,
            KeyAlgorithm: issuerKey.KeyAlgorithm,
            KeySize: issuerKey.KeySize);

        var hashForNonEd = HashAlgorithmName.SHA256;
        var signature = await signing.SignDataAsync(signingInputBytes, hashForNonEd, keyRef, ct);

        return $"{signingInput}.{Base64Url(signature)}";
    }

    public static JsonObject BuildVcHeader(VerificationMethod issuerKey)
    {
        var header = new JsonObject();
        header["alg"] = MapJwsAlgorithm(issuerKey.KeyAlgorithm);
        header["kid"] = issuerKey.MethodId;
        header["typ"] = "vc+jwt";
        return header;
    }

    public static JsonObject BuildVcPayload(
        string issuerDid,
        string subjectDid,
        string credentialId,
        IReadOnlyList<string> contexts,
        IReadOnlyList<string> types,
        JsonObject credentialSubjectClaims,
        DateTime issuedAt,
        DateTime? validUntil)
    {
        var iat = ToUnixSeconds(issuedAt);
        long? exp = validUntil.HasValue ? ToUnixSeconds(validUntil.Value) : null;

        // The credentialSubject embeds the subject DID under "id" and merges in claims.
        var credentialSubject = new JsonObject { ["id"] = subjectDid };
        foreach (var (key, value) in credentialSubjectClaims)
            credentialSubject[key] = value?.DeepClone();

        var vc = new JsonObject
        {
            ["@context"] = JsonArrayFromStrings(contexts),
            ["type"] = JsonArrayFromStrings(types),
            ["id"] = credentialId,
            ["issuer"] = issuerDid,
            ["validFrom"] = issuedAt.ToString("O"),
            ["credentialSubject"] = credentialSubject
        };
        if (validUntil.HasValue)
            vc["validUntil"] = validUntil.Value.ToString("O");

        var payload = new JsonObject
        {
            ["iss"] = issuerDid,
            ["sub"] = subjectDid,
            ["jti"] = credentialId,
            ["iat"] = iat,
            ["nbf"] = iat,
            ["vc"] = vc
        };
        if (exp.HasValue)
            payload["exp"] = exp.Value;

        return payload;
    }

    public static (string HeaderJson, string PayloadJson, byte[] Signature) Decompose(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) throw new FormatException("JWT must have 3 segments.");
        return (
            DecodeUtf8(parts[0]),
            DecodeUtf8(parts[1]),
            Base64UrlDecode(parts[2]));
    }

    public static byte[] SigningInputBytes(string jwt)
    {
        var idx = jwt.LastIndexOf('.');
        if (idx <= 0) throw new FormatException("JWT must have a signature segment.");
        return Encoding.ASCII.GetBytes(jwt[..idx]);
    }

    private static string MapJwsAlgorithm(string keyAlgorithm) => keyAlgorithm switch
    {
        "Ed25519" => "EdDSA",
        "ECDSA" => "ES256",
        "RSA" => "RS256",
        _ => throw new NotSupportedException($"No JWS alg mapping for key algorithm '{keyAlgorithm}'.")
    };

    private static readonly JsonSerializerOptions CompactJsonOptions = new()
    {
        WriteIndented = false,
        // Don't escape characters that aren't actually unsafe in JSON (e.g. '+', '/').
        // Otherwise "vc+jwt" serializes as "vc+jwt" — valid but hostile to humans/tools.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static string Serialize(JsonObject obj) => obj.ToJsonString(CompactJsonOptions);

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Base64Url(string text) => Base64Url(Encoding.UTF8.GetBytes(text));

    private static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }

    private static string DecodeUtf8(string segment) =>
        Encoding.UTF8.GetString(Base64UrlDecode(segment));

    private static long ToUnixSeconds(DateTime dt) =>
        new DateTimeOffset(dt.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(dt, DateTimeKind.Utc)
            : dt.ToUniversalTime()).ToUnixTimeSeconds();

    private static JsonArray JsonArrayFromStrings(IEnumerable<string> values)
    {
        var arr = new JsonArray();
        foreach (var v in values) arr.Add(v);
        return arr;
    }
}

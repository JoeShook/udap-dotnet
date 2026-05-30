#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using SimpleBase;
using Sigil.Common.Data;
using Sigil.Vc.ViewModels;

namespace Sigil.Vc.Services;

/// <summary>
/// Verifies a JWT-VC by resolving the issuer DID from the kid header, fetching the
/// verification method's public key, and checking the EdDSA signature.
/// Phase A: only Ed25519 (did:key); future phases extend to other key algorithms / methods.
/// </summary>
public class CredentialVerifier
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;

    public CredentialVerifier(IDbContextFactory<SigilDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<CredentialVerifyResult> VerifyAsync(string jwt, CancellationToken ct = default)
    {
        string headerJson, payloadJson;
        byte[] signature;
        byte[] signingInput;

        try
        {
            (headerJson, payloadJson, signature) = CredentialJwtBuilder.Decompose(jwt);
            signingInput = CredentialJwtBuilder.SigningInputBytes(jwt);
        }
        catch (Exception ex)
        {
            return new CredentialVerifyResult(false, $"Malformed JWT: {ex.Message}", null, null);
        }

        JsonObject header;
        try
        {
            header = JsonNode.Parse(headerJson) as JsonObject
                ?? throw new InvalidOperationException("Header is not a JSON object.");
        }
        catch (Exception ex)
        {
            return new CredentialVerifyResult(false, $"Header parse error: {ex.Message}", headerJson, payloadJson);
        }

        var alg = header["alg"]?.GetValue<string>();
        var kid = header["kid"]?.GetValue<string>();

        if (string.IsNullOrEmpty(alg) || string.IsNullOrEmpty(kid))
            return new CredentialVerifyResult(false, "Header missing alg or kid.", headerJson, payloadJson);

        if (!alg.Equals("EdDSA", StringComparison.Ordinal))
            return new CredentialVerifyResult(false, $"Phase A verifier supports EdDSA only, got '{alg}'.", headerJson, payloadJson);

        // kid format: did:method:id#fragment — issuer DID is everything before #.
        var hashIdx = kid.IndexOf('#');
        if (hashIdx < 0)
            return new CredentialVerifyResult(false, "kid is missing fragment.", headerJson, payloadJson);
        var issuerDid = kid[..hashIdx];

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var doc = await db.DidDocuments
            .Include(d => d.VerificationMethods)
            .FirstOrDefaultAsync(d => d.Did == issuerDid, ct);

        if (doc == null)
            return new CredentialVerifyResult(false, $"Unknown issuer DID: {issuerDid}", headerJson, payloadJson);
        if (doc.Deactivated)
            return new CredentialVerifyResult(false, $"Issuer DID is deactivated: {issuerDid}", headerJson, payloadJson);

        var vm = doc.VerificationMethods.FirstOrDefault(v => v.MethodId == kid);
        if (vm == null)
            return new CredentialVerifyResult(false, $"Verification method {kid} not found on issuer.", headerJson, payloadJson);

        if (!vm.KeyAlgorithm.Equals("Ed25519", StringComparison.OrdinalIgnoreCase))
            return new CredentialVerifyResult(false, $"Phase A verifier supports Ed25519 only, got '{vm.KeyAlgorithm}'.", headerJson, payloadJson);

        byte[] publicKeyBytes;
        try
        {
            publicKeyBytes = DecodeEd25519FromMultibase(vm.PublicKeyMultibase);
        }
        catch (Exception ex)
        {
            return new CredentialVerifyResult(false, $"Public key decode error: {ex.Message}", headerJson, payloadJson);
        }

        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(publicKeyBytes, 0));
        verifier.BlockUpdate(signingInput, 0, signingInput.Length);
        var ok = verifier.VerifySignature(signature);

        if (!ok)
            return new CredentialVerifyResult(false, "Signature did not verify.", headerJson, payloadJson);

        var expiry = TryGetExp(payloadJson);
        if (expiry.HasValue && DateTimeOffset.UtcNow > expiry.Value)
            return new CredentialVerifyResult(false, $"Credential expired at {expiry.Value:O}", headerJson, payloadJson);

        return new CredentialVerifyResult(true, "Verified.", headerJson, payloadJson);
    }

    private static byte[] DecodeEd25519FromMultibase(string multibase)
    {
        if (string.IsNullOrEmpty(multibase) || multibase[0] != 'z')
            throw new FormatException("publicKeyMultibase must start with 'z'.");
        var decoded = Base58.Bitcoin.Decode(multibase.AsSpan(1)).ToArray();
        if (decoded.Length != 34 || decoded[0] != 0xED || decoded[1] != 0x01)
            throw new FormatException("Not an Ed25519 multicodec multibase.");
        return decoded[2..];
    }

    private static DateTimeOffset? TryGetExp(string payloadJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.TryGetProperty("exp", out var expElem) &&
                expElem.ValueKind == JsonValueKind.Number)
            {
                return DateTimeOffset.FromUnixTimeSeconds(expElem.GetInt64());
            }
        }
        catch { /* ignore — treat as no exp */ }
        return null;
    }
}

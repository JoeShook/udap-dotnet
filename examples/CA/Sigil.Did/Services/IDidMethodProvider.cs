#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;

namespace Sigil.Did.Services;

/// <summary>
/// DID method implementation. One implementation per supported method (did:key, did:web, ...).
/// Resolved by name from registered providers in <see cref="DidIssuanceService"/>.
/// </summary>
public interface IDidMethodProvider
{
    /// <summary>Method name as used in DIDs, e.g. "key", "web", "jwk".</summary>
    string Method { get; }

    /// <summary>
    /// Mints a new DID under the given template + trust domain, using the supplied signing
    /// provider for key material. Returns everything <see cref="DidIssuanceService"/> needs
    /// to persist the DID Document and verification methods.
    /// </summary>
    Task<DidMintResult> MintAsync(
        DidTemplate template,
        TrustDomain trustDomain,
        ISigningProvider signingProvider,
        CancellationToken ct = default);
}

/// <summary>What a method provider returns after minting; consumed by the issuance service.</summary>
public record DidMintResult(
    string Did,
    string Method,
    IReadOnlyList<VerificationMethodSeed> VerificationMethods);

/// <summary>Verification method values needed to persist a <see cref="VerificationMethod"/> row.</summary>
public record VerificationMethodSeed(
    string MethodId,
    string KeyAlgorithm,
    string Provider,
    string KeyIdentifier,
    int KeySize,
    string PublicKeyMultibase,
    string Purposes);

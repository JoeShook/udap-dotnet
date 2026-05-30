#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Services.Signing;

/// <summary>
/// Raw public key material with algorithm identifier.
/// For Ed25519: 32 raw key bytes.
/// For RSA / ECDSA: DER-encoded SubjectPublicKeyInfo bytes.
/// Used by DID code that needs raw key bytes (e.g. did:key multicodec encoding).
/// </summary>
public record RawPublicKey(string Algorithm, byte[] Bytes);

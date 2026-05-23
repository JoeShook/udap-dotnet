#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Shouldly;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using Sigil.Did.Services;

namespace Sigil.Signing.Tests;

public class DidKeyMethodProviderTests
{
    private readonly DidKeyMethodProvider _provider = new();
    private readonly LocalSigningProvider _signing = new();

    [Fact]
    public async Task MintAsync_Ed25519_ProducesValidDidKey()
    {
        var template = new DidTemplate { Method = "key", KeyAlgorithm = "Ed25519", DefaultPurposes = "assertionMethod;authentication" };
        var trustDomain = new TrustDomain { Id = 1, Name = "test" };

        var result = await _provider.MintAsync(template, trustDomain, _signing);

        result.Method.ShouldBe("key");
        result.Did.ShouldStartWith("did:key:z");
        result.VerificationMethods.Count.ShouldBe(1);

        var vm = result.VerificationMethods[0];
        vm.KeyAlgorithm.ShouldBe("Ed25519");
        vm.PublicKeyMultibase.ShouldStartWith("z");
        vm.MethodId.ShouldBe($"{result.Did}#{vm.PublicKeyMultibase}");
        vm.Purposes.ShouldBe("assertionMethod;authentication");
    }

    [Fact]
    public async Task MintAsync_NonEd25519_Throws()
    {
        var template = new DidTemplate { Method = "key", KeyAlgorithm = "RSA" };
        var trustDomain = new TrustDomain { Id = 1, Name = "test" };

        await Should.ThrowAsync<NotSupportedException>(
            async () => await _provider.MintAsync(template, trustDomain, _signing));
    }

    [Fact]
    public async Task DecodeMultibase_RoundTripsPublicKey()
    {
        var template = new DidTemplate { Method = "key", KeyAlgorithm = "Ed25519", DefaultPurposes = "assertionMethod" };
        var trustDomain = new TrustDomain { Id = 1, Name = "test" };

        var mint = await _provider.MintAsync(template, trustDomain, _signing);
        var multibase = mint.VerificationMethods[0].PublicKeyMultibase;

        var (multicodec, raw) = DidKeyMethodProvider.DecodeMultibase(multibase);

        multicodec.ShouldBe(new byte[] { 0xED, 0x01 });
        raw.Length.ShouldBe(32);
    }

    [Fact]
    public async Task Mint_Then_SignAndVerify_RoundTrips()
    {
        var template = new DidTemplate { Method = "key", KeyAlgorithm = "Ed25519", DefaultPurposes = "assertionMethod" };
        var trustDomain = new TrustDomain { Id = 1, Name = "test" };

        var mint = await _provider.MintAsync(template, trustDomain, _signing);
        var vm = mint.VerificationMethods[0];

        var keyRef = new SigningKeyReference(vm.Provider, vm.KeyIdentifier, vm.KeyAlgorithm, vm.KeySize);

        var data = "hello world"u8.ToArray();
        var signature = await _signing.SignDataAsync(data, System.Security.Cryptography.HashAlgorithmName.SHA256, keyRef);

        var (_, rawPub) = DidKeyMethodProvider.DecodeMultibase(vm.PublicKeyMultibase);
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(rawPub, 0));
        verifier.BlockUpdate(data, 0, data.Length);

        verifier.VerifySignature(signature).ShouldBeTrue();
    }
}

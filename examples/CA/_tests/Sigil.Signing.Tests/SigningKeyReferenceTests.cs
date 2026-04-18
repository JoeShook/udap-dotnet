#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using FluentAssertions;
using Sigil.Common.Services.Signing;

namespace Sigil.Signing.Tests;

public class SigningKeyReferenceTests
{
    [Fact]
    public void Record_Equality_ByValue()
    {
        var ref1 = new SigningKeyReference("vault-transit", "key-1", "RSA", 4096);
        var ref2 = new SigningKeyReference("vault-transit", "key-1", "RSA", 4096);

        ref1.Should().Be(ref2);
    }

    [Fact]
    public void Record_Inequality_DifferentProvider()
    {
        var ref1 = new SigningKeyReference("vault-transit", "key-1", "RSA", 4096);
        var ref2 = new SigningKeyReference("gcp-kms", "key-1", "RSA", 4096);

        ref1.Should().NotBe(ref2);
    }

    [Fact]
    public void Record_Inequality_DifferentKeyIdentifier()
    {
        var ref1 = new SigningKeyReference("local", "aaa", "RSA", 2048);
        var ref2 = new SigningKeyReference("local", "bbb", "RSA", 2048);

        ref1.Should().NotBe(ref2);
    }

    [Fact]
    public void Deconstruction_Works()
    {
        var keyRef = new SigningKeyReference("gcp-kms", "sigil-abc123", "ECDSA", 384);

        var (provider, keyId, algorithm, size) = keyRef;

        provider.Should().Be("gcp-kms");
        keyId.Should().Be("sigil-abc123");
        algorithm.Should().Be("ECDSA");
        size.Should().Be(384);
    }
}

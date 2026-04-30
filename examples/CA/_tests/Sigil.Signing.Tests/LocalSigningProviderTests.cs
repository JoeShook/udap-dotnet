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
using FluentAssertions;
using Sigil.Common.Services.Signing;

namespace Sigil.Signing.Tests;

public class LocalSigningProviderTests : IDisposable
{
    private readonly LocalSigningProvider _provider = new();

    [Fact]
    public void ProviderName_ReturnsLocal()
    {
        _provider.ProviderName.Should().Be("local");
    }

    [Theory]
    [InlineData("RSA", 2048, null)]
    [InlineData("RSA", 4096, null)]
    [InlineData("ECDSA", 0, "nistp256")]
    [InlineData("ECDSA", 0, "nistp384")]
    public async Task GenerateKeyAsync_CreatesKeyAndReturnsReference(
        string algorithm, int keySize, string? curve)
    {
        var keyRef = await _provider.GenerateKeyAsync(algorithm, keySize, curve);

        keyRef.Provider.Should().Be("local");
        keyRef.KeyAlgorithm.Should().Be(algorithm);
        keyRef.KeyIdentifier.Should().NotBeNullOrEmpty();
        keyRef.KeySize.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task GetPublicKeyAsync_ReturnsRsaKey()
    {
        var keyRef = await _provider.GenerateKeyAsync("RSA", 2048);

        using var publicKey = await _provider.GetPublicKeyAsync(keyRef);

        publicKey.Should().BeAssignableTo<RSA>();
    }

    [Fact]
    public async Task GetPublicKeyAsync_ReturnsEcdsaKey()
    {
        var keyRef = await _provider.GenerateKeyAsync("ECDSA", 0, "nistp384");

        using var publicKey = await _provider.GetPublicKeyAsync(keyRef);

        publicKey.Should().BeAssignableTo<ECDsa>();
    }

    [Fact]
    public async Task GetPublicKeyAsync_ThrowsForUnknownKey()
    {
        var bogusRef = new SigningKeyReference("local", "nonexistent", "RSA", 2048);

        var act = () => _provider.GetPublicKeyAsync(bogusRef);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not found*");
    }

    [Fact]
    public async Task SignDataAsync_Rsa_ProducesVerifiableSignature()
    {
        var keyRef = await _provider.GenerateKeyAsync("RSA", 2048);
        var data = "test data to sign"u8.ToArray();

        var signature = await _provider.SignDataAsync(data, HashAlgorithmName.SHA256, keyRef);

        signature.Should().NotBeNullOrEmpty();

        // Verify the signature using the public key
        using var rsa = (RSA)await _provider.GetPublicKeyAsync(keyRef);
        var isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task SignDataAsync_Ecdsa_ProducesVerifiableSignature()
    {
        var keyRef = await _provider.GenerateKeyAsync("ECDSA", 0, "nistp384");
        var data = "test data to sign"u8.ToArray();

        var signature = await _provider.SignDataAsync(data, HashAlgorithmName.SHA384, keyRef);

        signature.Should().NotBeNullOrEmpty();

        // Verify the signature using the public key
        using var ecdsa = (ECDsa)await _provider.GetPublicKeyAsync(keyRef);
        var isValid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA384);
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task SignDataAsync_ThrowsForUnknownKey()
    {
        var bogusRef = new SigningKeyReference("local", "nonexistent", "RSA", 2048);
        var data = "test"u8.ToArray();

        var act = () => _provider.SignDataAsync(data, HashAlgorithmName.SHA256, bogusRef);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not found*");
    }

    [Fact]
    public async Task SignDataAsync_DifferentData_ProducesDifferentSignatures()
    {
        var keyRef = await _provider.GenerateKeyAsync("RSA", 2048);
        var data1 = "first message"u8.ToArray();
        var data2 = "second message"u8.ToArray();

        var sig1 = await _provider.SignDataAsync(data1, HashAlgorithmName.SHA256, keyRef);
        var sig2 = await _provider.SignDataAsync(data2, HashAlgorithmName.SHA256, keyRef);

        sig1.Should().NotBeEquivalentTo(sig2);
    }

    [Fact]
    public async Task GenerateKeyAsync_EachCallCreatesUniqueKey()
    {
        var keyRef1 = await _provider.GenerateKeyAsync("RSA", 2048);
        var keyRef2 = await _provider.GenerateKeyAsync("RSA", 2048);

        keyRef1.KeyIdentifier.Should().NotBe(keyRef2.KeyIdentifier);
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public async Task SignDataAsync_Rsa_SupportsMultipleHashAlgorithms(string hashName)
    {
        var hashAlgorithm = new HashAlgorithmName(hashName);
        var keyRef = await _provider.GenerateKeyAsync("RSA", 2048);
        var data = "hash algorithm test"u8.ToArray();

        var signature = await _provider.SignDataAsync(data, hashAlgorithm, keyRef);

        signature.Should().NotBeNullOrEmpty();

        using var rsa = (RSA)await _provider.GetPublicKeyAsync(keyRef);
        rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    public void Dispose()
    {
        _provider.Dispose();
    }
}

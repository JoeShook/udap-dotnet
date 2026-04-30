#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Udap.Tefca.Model;
using Xunit;

namespace Udap.Common.Tests.Model.Tefca;

/// <summary>
/// Tests for <see cref="TefcaCertificationDocument"/>.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">
/// SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 Registration #6</a>
/// </summary>
public class TefcaCertificationDocumentTests
{
    [Fact]
    public void Constructor_Sets_CertificationName_And_Uris()
    {
        var doc = new TefcaCertificationDocument();

        Assert.Equal(TefcaConstants.Certification.BasicAppCertificationName, doc.CertificationName);
        Assert.Single(doc.CertificationUris!);
        Assert.Contains(TefcaConstants.Certification.BasicAppCertificationUri, doc.CertificationUris!);
    }

    [Fact]
    public void Serialize_Includes_ExchangePurposes()
    {
        var doc = new TefcaCertificationDocument
        {
            ExchangePurposes = [TefcaConstants.ExchangePurposeCodes.Treatment]
        };

        var json = doc.SerializeToJson();
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;

        Assert.True(root.TryGetProperty("exchange_purposes", out var xp));
        Assert.Equal(JsonValueKind.Array, xp.ValueKind);
        Assert.Single(xp.EnumerateArray());
        Assert.Equal("T-TREAT", xp[0].GetString());
    }

    [Fact]
    public void Serialize_Includes_HomeCommunityId()
    {
        var doc = new TefcaCertificationDocument
        {
            HomeCommunityId = "urn:oid:1.2.3.4.5"
        };

        var json = doc.SerializeToJson();
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;

        Assert.True(root.TryGetProperty("home_community_id", out var hcid));
        Assert.Equal("urn:oid:1.2.3.4.5", hcid.GetString());
    }

    [Fact]
    public void Serialize_Includes_Base_And_Tefca_Claims()
    {
        var doc = new TefcaCertificationDocument
        {
            Issuer = "https://rce.example.com",
            Subject = "https://app.example.com",
            ExchangePurposes = [TefcaConstants.ExchangePurposeCodes.IndividualAccessServices],
            HomeCommunityId = "urn:oid:1.2.3.4.5"
        };

        var json = doc.SerializeToJson();
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;

        // Base claims
        Assert.True(root.TryGetProperty("iss", out var iss));
        Assert.Equal("https://rce.example.com", iss.GetString());
        Assert.True(root.TryGetProperty("certification_name", out var cn));
        Assert.Equal("TEFCA Basic App Certification", cn.GetString());
        Assert.True(root.TryGetProperty("certification_uris", out _));

        // TEFCA claims
        Assert.True(root.TryGetProperty("exchange_purposes", out var xp));
        Assert.Equal("T-IAS", xp[0].GetString());
        Assert.True(root.TryGetProperty("home_community_id", out _));
    }

    [Fact]
    public void Roundtrip_Deserialization()
    {
        var doc = new TefcaCertificationDocument
        {
            Issuer = "https://rce.example.com",
            Subject = "https://app.example.com",
            ExchangePurposes = [TefcaConstants.ExchangePurposeCodes.TefcaRequiredTreatment],
            HomeCommunityId = "urn:oid:9.8.7.6"
        };

        var json = doc.SerializeToJson();
        var deserialized = JsonSerializer.Deserialize<TefcaCertificationDocument>(json);

        Assert.NotNull(deserialized);
        Assert.Equal("TEFCA Basic App Certification", deserialized.CertificationName);
        Assert.Single(deserialized.ExchangePurposes!);
        Assert.Contains("T-TRTMNT", deserialized.ExchangePurposes!);
        Assert.Equal("urn:oid:9.8.7.6", deserialized.HomeCommunityId);
    }
}

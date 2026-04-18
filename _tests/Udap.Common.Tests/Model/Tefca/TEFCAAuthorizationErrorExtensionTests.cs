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
/// Tests for <see cref="TEFCAAuthorizationErrorExtension"/>.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">
/// SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 B2B #3, Table 1</a>
/// </summary>
public class TEFCAAuthorizationErrorExtensionTests
{
    [Fact]
    public void Serialize_ConsentRequired_Only()
    {
        var error = new TEFCAAuthorizationErrorExtension
        {
            ConsentRequired = ["urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1"]
        };

        var json = JsonSerializer.Serialize(error);
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;

        Assert.True(root.TryGetProperty("consent_required", out var cr));
        Assert.Equal(JsonValueKind.Array, cr.ValueKind);
        Assert.Single(cr.EnumerateArray());
        Assert.Equal("urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1", cr[0].GetString());

        Assert.True(root.TryGetProperty("consent_form", out var cf));
        Assert.Equal(JsonValueKind.Null, cf.ValueKind);
    }

    [Fact]
    public void Serialize_ConsentRequired_With_ConsentForm()
    {
        var error = new TEFCAAuthorizationErrorExtension
        {
            ConsentRequired = [
                "urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1",
                "urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.2"
            ],
            ConsentForm = "https://tefca.example.com/consent/form.pdf"
        };

        var json = JsonSerializer.Serialize(error);
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;

        Assert.True(root.TryGetProperty("consent_required", out var cr));
        Assert.Equal(2, cr.GetArrayLength());

        Assert.True(root.TryGetProperty("consent_form", out var cf));
        Assert.Equal("https://tefca.example.com/consent/form.pdf", cf.GetString());
    }

    [Fact]
    public void Roundtrip_Deserialization()
    {
        var original = new TEFCAAuthorizationErrorExtension
        {
            ConsentRequired = ["urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1"],
            ConsentForm = "https://tefca.example.com/consent/form.pdf"
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<TEFCAAuthorizationErrorExtension>(json);

        Assert.NotNull(deserialized);
        Assert.Single(deserialized.ConsentRequired);
        Assert.Contains("urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1", deserialized.ConsentRequired);
        Assert.Equal("https://tefca.example.com/consent/form.pdf", deserialized.ConsentForm);
    }

    [Fact]
    public void Default_ConsentRequired_Is_Empty()
    {
        var error = new TEFCAAuthorizationErrorExtension();
        Assert.Empty(error.ConsentRequired);
        Assert.Null(error.ConsentForm);
    }
}

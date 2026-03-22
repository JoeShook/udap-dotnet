#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Udap.Model.Registration;

namespace Udap.Tefca.Model;

/// <summary>
/// TEFCA-specific certification document extending the base UDAP certification
/// with claims required by the Facilitated FHIR Implementation SOP.
///
/// The basic-app-certification JWT MUST contain:
/// - certification_name: "TEFCA Basic App Certification"
/// - certification_uris: ["https://rce.sequoiaproject.org/udap/profiles/basic-app-certification"]
/// - exchange_purposes: Array of one Exchange Purpose from the TEFCA Exchange Purposes SOP
/// - home_community_id: The HomeCommunityId of the Node making the registration request
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 Registration #6</a>
/// </summary>
public class TefcaCertificationDocument : UdapCertificationAndEndorsementDocument
{
    public TefcaCertificationDocument()
        : base(TefcaConstants.Certification.BasicAppCertificationName)
    {
        CertificationUris = [TefcaConstants.Certification.BasicAppCertificationUri];
    }

    /// <summary>
    /// An array of one Exchange Purpose from the TEFCA Exchange Purposes SOP.
    /// </summary>
    [JsonPropertyName(TefcaConstants.Certification.ExchangePurposes)]
    public ICollection<string>? ExchangePurposes { get; set; }

    /// <summary>
    /// The HomeCommunityId of the Node making the registration request.
    /// </summary>
    [JsonPropertyName(TefcaConstants.Certification.HomeCommunityId)]
    public string? HomeCommunityId { get; set; }

    /// <inheritdoc />
    public override string SerializeToJson()
    {
        return JsonSerializer.Serialize(this);
    }
}

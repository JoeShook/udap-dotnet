#region (c) 2023 Joseph Shook. All rights reserved.
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
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Tefca.Model;

/// <summary>
/// TEFCA IAS Authorization Extension Object.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP: Facilitated FHIR Implementation v2.0 — Section 6.11 IAS, Table 4</a>
/// </summary>
public class TEFCAIASAuthorizationExtension : IAuthorizationExtensionObject
{
    private string _version = "1";
    private JsonElement? _userInformation;
    private JsonElement? _patientInformation;
    private ICollection<string>? _consentPolicy;
    private ICollection<string>? _consentReference;
    private JsonElement? _idToken;

    public TEFCAIASAuthorizationExtension()
    {
        Version = _version;
        ConsentPolicy = [];
        ConsentReference = [];
    }

    /// <summary>
    /// version required
    ///
    /// String with fixed value: "1"
    /// </summary>
    [JsonPropertyName(TefcaConstants.TEFCAIASAuthorizationExtension.Version)]
    public string Version
    {
        get => _version;
        set => _version = value;
    }

    /// <summary>
    /// user_information required:
    ///
    /// FHIR RelatedPerson Resource with all known
    /// demographics. Where the user is the patient, the value of
    /// the relationship element MUST be "ONESELF"
    /// </summary>
    [JsonPropertyName(TefcaConstants.TEFCAIASAuthorizationExtension.UserInformation)]
    public JsonElement? UserInformation
    {
        get => _userInformation;
        set => _userInformation = value;
    }

    /// <summary>
    /// patient_information required:
    ///
    /// FHIR US Core Patient Resource with all known and validated demographics
    /// </summary>
    [JsonPropertyName(TefcaConstants.TEFCAIASAuthorizationExtension.PatientInformation)]
    public JsonElement? PatientInformation
    {
        get => _patientInformation;
        set => _patientInformation = value;
    }

    /// <summary>
    /// consent_policy required:
    ///
    /// The Access Consent Policy Identifier corresponding to the asserted
    /// Access Policy that represents the identity proofing level of assurance
    /// of the user, array of string values from the subset of valid policy
    /// OIDs in that represent identity proofing levels of assurance, each
    /// expressed as a URI, e.g. ["urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1"]
    /// </summary>
    [JsonPropertyName(TefcaConstants.TEFCAIASAuthorizationExtension.ConsentPolicy)]
    public ICollection<string>? ConsentPolicy
    {
        get => _consentPolicy;
        set => _consentPolicy = value;
    }

    /// <summary>
    /// consent_reference optional:
    ///
    /// An array of FHIR Document Reference or Consent Resources where the
    /// supporting access consent documentation can be retrieved, each
    /// expressed as an absolute URL,
    /// e.g. ["https://tefca.example.com/fhir/R4/DocumentReference/consent-6461766570"]
    /// </summary>
    [JsonPropertyName(TefcaConstants.TEFCAIASAuthorizationExtension.ConsentReference)]
    public ICollection<string>? ConsentReference
    {
        get => _consentReference;
        set => _consentReference = value;
    }

    /// <summary>
    /// id_token required:
    ///
    /// The CSP-provided OpenID Connect token as further defined in
    /// the Exchange Purpose (XP) Implementation SOP: Individual Access Services (IAS).
    /// Responding server SHOULD respond with invalid_grant if missing.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP v2.0 — Table 4</a>
    /// </summary>
    [JsonPropertyName(TefcaConstants.TEFCAIASAuthorizationExtension.IdToken)]
    public JsonElement? IdToken
    {
        get => _idToken;
        set => _idToken = value;
    }

    /// <inheritdoc />
    public List<string> Validate()
    {
        var notes = new List<string>();

        if (string.IsNullOrWhiteSpace(Version))
        {
            notes.Add($"Missing required {TefcaConstants.TEFCAIASAuthorizationExtension.Version}");
        }

        if (!UserInformation.HasValue || string.IsNullOrEmpty(UserInformation.Value.ToString()))
        {
            notes.Add($"Missing required {TefcaConstants.TEFCAIASAuthorizationExtension.UserInformation}");
        }

        if (!PatientInformation.HasValue || string.IsNullOrEmpty(PatientInformation.Value.ToString()))
        {
            notes.Add($"Missing required {TefcaConstants.TEFCAIASAuthorizationExtension.PatientInformation}");
        }

        return notes;
    }

    /// <inheritdoc />
    public ICollection<string>? GetPurposeOfUse() => null;

    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    public virtual string SerializeToJson(bool indent = false)
    {
        return JsonSerializer.Serialize(this, indent ? IndentedOptions : DefaultOptions);
    }

    private static readonly JsonSerializerOptions DefaultOptions = new JsonSerializerOptions { WriteIndented = false };
    private static readonly JsonSerializerOptions IndentedOptions = new JsonSerializerOptions { WriteIndented = true };
}

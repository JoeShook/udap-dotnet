#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;

namespace Udap.Server.Configuration;

/// <summary>
/// Per-community overrides for <see cref="ServerSettings"/>.
/// When a client belongs to a community that has a matching entry here,
/// these settings take precedence over the global defaults.
/// </summary>
public class CommunityServerSettings
{
    /// <summary>
    /// The community name (e.g., "udap://fhirlabs.net") used to match
    /// against the client's registered community.
    /// </summary>
    [JsonPropertyName("Community")]
    public string Community { get; set; } = string.Empty;

    /// <summary>
    /// Authorization extension key names required by this community in every
    /// token request (e.g., ["hl7-b2b"]).  When null, falls back to the
    /// global <see cref="ServerSettings.AuthorizationExtensionsRequired"/>.
    /// </summary>
    [JsonPropertyName("AuthorizationExtensionsRequired")]
    public HashSet<string>? AuthorizationExtensionsRequired { get; set; }

    /// <summary>
    /// Allowed purpose_of_use codes for this community.  When set, every code
    /// in the extension's purpose_of_use array must appear in this set.
    /// When null, falls back to the global <see cref="ServerSettings.AllowedPurposeOfUse"/>.
    /// An empty set means no purpose_of_use codes are accepted.
    /// <para>
    /// SSRAA communities typically use HL7 v3 PurposeOfUse codes
    /// (e.g., "urn:oid:2.16.840.1.113883.5.8#TREAT").
    /// TEFCA communities use XP codes
    /// (e.g., "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT").
    /// </para>
    /// </summary>
    [JsonPropertyName("AllowedPurposeOfUse")]
    public HashSet<string>? AllowedPurposeOfUse { get; set; }

    /// <summary>
    /// Maximum number of purpose_of_use entries allowed in the extension.
    /// When null, falls back to the global <see cref="ServerSettings.MaxPurposeOfUseCount"/>.
    /// TEFCA requires exactly 1; base SSRAA allows multiple.
    /// </summary>
    [JsonPropertyName("MaxPurposeOfUseCount")]
    public int? MaxPurposeOfUseCount { get; set; }
}

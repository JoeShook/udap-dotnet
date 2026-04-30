#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Validation;

/// <summary>
/// Validation rules declared by a community token validator for a specific grant type.
/// When a <see cref="ICommunityTokenValidator"/> returns non-null rules from
/// <see cref="ICommunityTokenValidator.GetValidationRules"/>, these override
/// global <c>ServerSettings</c> for that community.
/// </summary>
public class CommunityValidationRules
{
    /// <summary>
    /// Extension keys that must be present in the token request (e.g., "hl7-b2b").
    /// Null means no requirement; empty set means explicitly no extensions required.
    /// </summary>
    public HashSet<string>? RequiredExtensions { get; init; }

    /// <summary>
    /// Allowed purpose_of_use codes. Null means no restriction.
    /// </summary>
    public HashSet<string>? AllowedPurposeOfUse { get; init; }

    /// <summary>
    /// Maximum number of purpose_of_use entries allowed. Null means no limit.
    /// </summary>
    public int? MaxPurposeOfUseCount { get; init; }
}

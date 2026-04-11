#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Tefca.Server;

/// <summary>
/// Configuration options for TEFCA community validators.
/// Maps community names to the TEFCA validation pipeline,
/// allowing the same validators to apply to multiple communities
/// regardless of their naming convention.
/// </summary>
public class TefcaValidationOptions
{
    /// <summary>
    /// Community names that should use TEFCA validation rules.
    /// Defaults to <see cref="Udap.Tefca.Model.TefcaConstants.CommunityUri"/>.
    /// </summary>
    public HashSet<string> Communities { get; set; } = new(StringComparer.Ordinal)
    {
        Udap.Tefca.Model.TefcaConstants.CommunityUri
    };
}

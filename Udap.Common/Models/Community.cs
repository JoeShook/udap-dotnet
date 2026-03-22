#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Models;

/// <summary>
/// Represents a UDAP community, which groups trust anchors, certifications, and
/// configuration for a set of participants sharing common trust policies.
/// </summary>
public class Community
{
    /// <summary>Gets or sets the database identifier.</summary>
    public int Id { get; set; }

    /// <summary>Gets or sets the community name, typically a URI (e.g., <c>udap://fhirlabs.net</c>).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets whether this community is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets whether this is the default community used when no community is specified.</summary>
    public bool Default { get; set; }

    /// <summary>Gets or sets the trust anchors associated with this community.</summary>
    public ICollection<Anchor>? Anchors { get; set; }

    /// <summary>Gets or sets the certifications associated with this community.</summary>
    public ICollection<Certification>? Certifications { get; set; }
}
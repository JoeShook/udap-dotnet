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
/// Represents a UDAP certification that can be associated with a community,
/// indicating compliance with specific trust framework requirements.
/// </summary>
public class Certification
{
    /// <summary>Gets or sets the database identifier.</summary>
    public long Id { get; set; }

    /// <summary>Gets or sets the certification name.</summary>
    public string Name { get; set; } = string.Empty;
}
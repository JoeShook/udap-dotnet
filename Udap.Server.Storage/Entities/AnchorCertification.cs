﻿#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Storage.Entities;

/// <summary>
/// This is an "associate" table, to map a many to many relationship 
/// </summary>
public class AnchorCertification
{
    public virtual Anchor Anchor { get; set; } = default!;
    public int AnchorId { get; set; }
    public virtual Certification Certification { get; set; } = default!;
    public int CertificationId { get; set; }
}
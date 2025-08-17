﻿#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Storage.Entities;

public class Certification
{
    public int Id { get; set; }
    
    public string Name { get; set; } = default!;

    public virtual ICollection<CommunityCertification> CommunityCertifications { get; set; } = default!;

    public virtual ICollection<AnchorCertification> AnchorCertifications { get; set; } = default!;
}
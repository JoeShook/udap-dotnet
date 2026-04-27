#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Data.Entities;

public class CommunityBaseUrl
{
    public int Id { get; set; }
    public int CommunityId { get; set; }
    public Community Community { get; set; } = null!;
    public string Url { get; set; } = string.Empty;
    public int SortOrder { get; set; }
}

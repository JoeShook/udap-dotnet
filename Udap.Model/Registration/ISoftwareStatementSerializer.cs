#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Model.Registration;

public interface ISoftwareStatementSerializer
{
    public string SerializeToJson();
    public string Base64UrlEncode();
}
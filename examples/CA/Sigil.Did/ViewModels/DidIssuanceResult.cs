#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Did.ViewModels;

public record DidIssuanceResult(
    int DidDocumentId,
    string Did,
    string DidDocumentJson);

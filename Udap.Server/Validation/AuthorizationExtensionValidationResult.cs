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
/// Result of validating authorization extension objects from a client assertion JWT.
/// </summary>
public class AuthorizationExtensionValidationResult
{
    public bool IsValid { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }

    public static AuthorizationExtensionValidationResult Success()
        => new() { IsValid = true };

    public static AuthorizationExtensionValidationResult Failure(string error, string description)
        => new() { IsValid = false, Error = error, ErrorDescription = description };
}

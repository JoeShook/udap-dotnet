#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;

namespace Udap.Server.Validation;

/// <summary>
/// Result of validating authorization extension objects from a client assertion JWT.
/// </summary>
public class AuthorizationExtensionValidationResult
{
    public bool IsValid { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// Optional error extension data to include in the error response "extensions" object.
    /// Keys are extension names (e.g., "hl7-b2b"), values are serializable objects.
    /// Used by trust community profiles (e.g., TEFCA) to return additional error metadata
    /// such as required consent policies.
    /// </summary>
    public Dictionary<string, object>? ErrorExtensions { get; set; }

    public static AuthorizationExtensionValidationResult Success()
        => new() { IsValid = true };

    public static AuthorizationExtensionValidationResult Failure(string error, string description)
        => new() { IsValid = false, Error = error, ErrorDescription = description };

    public static AuthorizationExtensionValidationResult Failure(
        string error, string description, Dictionary<string, object> errorExtensions)
        => new() { IsValid = false, Error = error, ErrorDescription = description, ErrorExtensions = errorExtensions };
}

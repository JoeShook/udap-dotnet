#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Registration;

/// <summary>
/// Result of the UDAP Dynamic Client Registration processor.
/// </summary>
public class UdapDynamicClientRegistrationProcessorResult
{
    private UdapDynamicClientRegistrationProcessorResult() { }

    public UdapDynamicClientRegistrationProcessorResult(string error, string? errorDescription = null)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    /// <summary>
    /// True if this is an upsert (client already existed and was updated).
    /// False if this is a new client creation.
    /// </summary>
    public bool IsUpsert { get; private init; }

    /// <summary>
    /// True if this was a cancel registration (empty grant types).
    /// </summary>
    public bool IsCancellation { get; private init; }

    public string? Error { get; }
    public string? ErrorDescription { get; }
    public bool IsError => !string.IsNullOrWhiteSpace(Error);

    public static UdapDynamicClientRegistrationProcessorResult Success(bool isUpsert) =>
        new() { IsUpsert = isUpsert };

    public static UdapDynamicClientRegistrationProcessorResult Cancelled() =>
        new() { IsCancellation = true };

    public static UdapDynamicClientRegistrationProcessorResult CancellationFailed() =>
        new("invalid_client_metadata", "No clients found to cancel");
}

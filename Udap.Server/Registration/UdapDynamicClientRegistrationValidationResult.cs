#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model.Registration;

namespace Udap.Server.Registration;

public class UdapDynamicClientRegistrationValidationResult
{
    public UdapDynamicClientRegistrationValidationResult(UdapDynamicClientRegistrationDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        Document = document;
    }

    public UdapDynamicClientRegistrationValidationResult(string error, string? errorDescription = null)
    {
        ArgumentNullException.ThrowIfNull(error);

        Error = error;
        ErrorDescription = errorDescription;
    }

    public UdapDynamicClientRegistrationDocument? Document;

    public string? Error { get; }

    public string? ErrorDescription { get; }

    public bool IsError => !string.IsNullOrWhiteSpace(Error);
}
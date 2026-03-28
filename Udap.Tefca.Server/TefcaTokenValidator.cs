#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Validation;
using Udap.Tefca.Model;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates that the <c>purpose_of_use</c> in the hl7-b2b Authorization Extension Object
/// matches the exchange purpose coded in the client's registered SAN URI.
///
/// Per SOP v2.0 Section 6.11 #4, each client registration is scoped to one exchange purpose.
/// The <c>purpose_of_use</c> in a token request must match that registered purpose.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=15">
/// SOP v2.0 — Table 2: TEFCA Specific HL7-B2B Extension Requirements</a>
/// </summary>
public class TefcaTokenValidator : ICommunityTokenValidator
{
    /// <inheritdoc />
    public bool AppliesToCommunity(string communityName)
        => communityName == TefcaConstants.CommunityUri;

    /// <inheritdoc />
    public Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context)
    {
        if (string.IsNullOrEmpty(context.SanUri))
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                "TEFCA client has no registered SAN URI"));
        }

        var hashIndex = context.SanUri.LastIndexOf('#');
        if (hashIndex < 0 || hashIndex == context.SanUri.Length - 1)
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                "TEFCA client's registered SAN URI does not contain an exchange purpose"));
        }

        var registeredXp = context.SanUri.Substring(hashIndex + 1);

        if (context.Extensions == null || context.Extensions.Count == 0)
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Success());
        }

        foreach (var (key, value) in context.Extensions)
        {
            if (value is IAuthorizationExtensionObject extObj)
            {
                var purposeOfUse = extObj.GetPurposeOfUse();
                if (purposeOfUse == null || purposeOfUse.Count == 0)
                {
                    continue;
                }

                foreach (var code in purposeOfUse)
                {
                    // Extract XP code from full URI format: urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT
                    var pouCode = code;
                    var pouHashIndex = code.LastIndexOf('#');
                    if (pouHashIndex >= 0 && pouHashIndex < code.Length - 1)
                    {
                        pouCode = code.Substring(pouHashIndex + 1);
                    }

                    if (!string.Equals(pouCode, registeredXp, StringComparison.Ordinal))
                    {
                        return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                            "invalid_grant",
                            $"purpose_of_use '{pouCode}' does not match registered exchange purpose '{registeredXp}'"));
                    }
                }
            }
        }

        return Task.FromResult(AuthorizationExtensionValidationResult.Success());
    }
}

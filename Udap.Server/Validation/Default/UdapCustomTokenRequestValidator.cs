#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Duende.IdentityServer.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Udap.Model;
using Udap.Server.Storage;

namespace Udap.Server.Validation.Default;

/// <summary>
/// Custom token request validator that enforces UDAP authorization extension
/// requirements (e.g., hl7-b2b, hl7-b2b-user, tefca-ias) for UDAP clients.
/// Runs after client authentication succeeds, returning <c>invalid_grant</c>
/// with a descriptive error when required extensions are missing or invalid.
/// </summary>
public class UdapCustomTokenRequestValidator : ICustomTokenRequestValidator
{
    private readonly IUdapAuthorizationExtensionValidator _extensionValidator;
    private readonly ILogger<UdapCustomTokenRequestValidator> _logger;

    public UdapCustomTokenRequestValidator(
        IUdapAuthorizationExtensionValidator extensionValidator,
        ILogger<UdapCustomTokenRequestValidator> logger)
    {
        _extensionValidator = extensionValidator;
        _logger = logger;
    }

    public async Task ValidateAsync(CustomTokenRequestValidationContext context)
    {
        var request = context.Result?.ValidatedRequest;

        if (request == null || !IsUdapClient(request))
        {
            return;
        }

        var clientAssertion = request.Secret?.Credential as string;
        if (clientAssertion == null)
        {
            return;
        }

        var tokenHandler = new JsonWebTokenHandler();
        JsonWebToken jwtToken;

        try
        {
            jwtToken = tokenHandler.ReadJsonWebToken(clientAssertion);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read client assertion JWT for extension validation");
            return;
        }

        Dictionary<string, object>? extensions = null;

        if (jwtToken.TryGetPayloadValue<JsonElement>(UdapConstants.JwtClaimTypes.Extensions, out var extensionsElement)
            && extensionsElement.ValueKind == JsonValueKind.Object)
        {
            extensions = PayloadSerializer.Deserialize(extensionsElement);
        }

        var communityId = request.Client.ClientSecrets
            .FirstOrDefault(s => s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
            ?.Value;

        var extensionContext = new UdapAuthorizationExtensionValidationContext
        {
            ClientAssertionToken = jwtToken,
            ClientId = request.ClientId ?? string.Empty,
            Extensions = extensions,
            CommunityId = communityId,
            GrantType = request.GrantType
        };

        var result = await _extensionValidator.ValidateAsync(extensionContext);

        if (!result.IsValid)
        {
            _logger.LogError(
                "Authorization extension validation failed for client_id {ClientId}: {Error}",
                request.ClientId, result.ErrorDescription);

            context.Result = new TokenRequestValidationResult(
                request,
                result.Error ?? "invalid_grant",
                result.ErrorDescription);
        }
    }

    private static bool IsUdapClient(ValidatedTokenRequest request)
    {
        return request.Client.ClientSecrets
            .Any(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME);
    }
}

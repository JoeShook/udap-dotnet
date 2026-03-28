#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Configuration;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Validation.Default;

/// <summary>
/// Default implementation of <see cref="IUdapAuthorizationExtensionValidator"/> that
/// enforces required authorization extensions based on <see cref="ServerSettings"/>
/// with optional per-community overrides via <see cref="CommunityServerSettings"/>.
/// </summary>
public class DefaultUdapAuthorizationExtensionValidator : IUdapAuthorizationExtensionValidator
{
    private readonly IOptionsMonitor<ServerSettings> _serverSettings;
    private readonly IUdapClientRegistrationStore _clientStore;
    private readonly IEnumerable<ICommunityTokenValidator> _communityTokenValidators;
    private readonly ILogger<DefaultUdapAuthorizationExtensionValidator> _logger;

    public DefaultUdapAuthorizationExtensionValidator(
        IOptionsMonitor<ServerSettings> serverSettings,
        IUdapClientRegistrationStore clientStore,
        IEnumerable<ICommunityTokenValidator> communityTokenValidators,
        ILogger<DefaultUdapAuthorizationExtensionValidator> logger)
    {
        _serverSettings = serverSettings;
        _clientStore = clientStore;
        _communityTokenValidators = communityTokenValidators;
        _logger = logger;
    }

    public async Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context)
    {
        var resolved = await ResolveCommunitySettingsAsync(context.CommunityId, context.GrantType);

        var requiredExtensions = resolved.RequiredExtensions;

        if (requiredExtensions == null || requiredExtensions.Count == 0)
        {
            return AuthorizationExtensionValidationResult.Success();
        }

        if (context.Extensions == null || context.Extensions.Count == 0)
        {
            _logger.LogError(
                "Client {ClientId} did not include required authorization extensions: {Required}",
                context.ClientId, string.Join(", ", requiredExtensions));

            return AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                $"Required authorization extension(s) missing: {string.Join(", ", requiredExtensions)}");
        }

        foreach (var required in requiredExtensions)
        {
            if (!context.Extensions.ContainsKey(required))
            {
                _logger.LogError(
                    "Client {ClientId} missing required authorization extension '{Extension}'",
                    context.ClientId, required);

                return AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    $"Required authorization extension '{required}' not found");
            }
        }

        foreach (var (key, value) in context.Extensions)
        {
            var errors = ValidateExtensionObject(key, value);

            if (errors.Count > 0)
            {
                _logger.LogError(
                    "Client {ClientId} authorization extension '{Extension}' validation failed: {Errors}",
                    context.ClientId, key, string.Join("; ", errors));

                return AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    $"Authorization extension '{key}' validation failed: {string.Join("; ", errors)}");
            }

            var pouResult = ValidatePurposeOfUse(
                key, value, resolved.AllowedPurposeOfUse, resolved.MaxPurposeOfUseCount,
                resolved.IsCommunityResolved, context.ClientId);

            if (!pouResult.IsValid)
            {
                return pouResult;
            }
        }

        // Community-specific token validation
        if (!string.IsNullOrEmpty(resolved.CommunityName))
        {
            context.CommunityName = resolved.CommunityName;

            foreach (var communityValidator in _communityTokenValidators)
            {
                if (communityValidator.AppliesToCommunity(resolved.CommunityName))
                {
                    var communityResult = await communityValidator.ValidateAsync(context);
                    if (!communityResult.IsValid)
                    {
                        return communityResult;
                    }
                }
            }
        }

        return AuthorizationExtensionValidationResult.Success();
    }

    private async Task<ResolvedSettings> ResolveCommunitySettingsAsync(string? communityId, string? grantType)
    {
        var settings = _serverSettings.CurrentValue;

        if (communityId != null && settings.CommunitySettings is { Count: > 0 })
        {
            foreach (var commSettings in settings.CommunitySettings)
            {
                var resolvedId = await _clientStore.GetCommunityId(commSettings.Community);

                if (resolvedId?.ToString() == communityId)
                {
                    return new ResolvedSettings
                    {
                        IsCommunityResolved = true,
                        CommunityName = commSettings.Community,
                        RequiredExtensions = ResolveRequiredExtensions(
                            grantType,
                            commSettings.ClientCredentialsExtensionsRequired,
                            commSettings.AuthorizationCodeExtensionsRequired,
                            commSettings.AuthorizationExtensionsRequired
                                ?? settings.AuthorizationExtensionsRequired),
                        AllowedPurposeOfUse = commSettings.AllowedPurposeOfUse,
                        MaxPurposeOfUseCount = commSettings.MaxPurposeOfUseCount
                    };
                }
            }
        }

        return new ResolvedSettings
        {
            RequiredExtensions = ResolveRequiredExtensions(
                grantType,
                settings.ClientCredentialsExtensionsRequired,
                settings.AuthorizationCodeExtensionsRequired,
                settings.AuthorizationExtensionsRequired),
            AllowedPurposeOfUse = settings.AllowedPurposeOfUse,
            MaxPurposeOfUseCount = settings.MaxPurposeOfUseCount
        };
    }

    /// <summary>
    /// Resolves the required extensions for the given grant type.
    /// Grant-type-specific settings take precedence over the general fallback.
    /// </summary>
    private static HashSet<string>? ResolveRequiredExtensions(
        string? grantType,
        HashSet<string>? clientCredentialsExtensions,
        HashSet<string>? authorizationCodeExtensions,
        HashSet<string>? fallback)
    {
        var grantSpecific = grantType switch
        {
            "client_credentials" => clientCredentialsExtensions,
            "authorization_code" => authorizationCodeExtensions,
            _ => null
        };

        return grantSpecific ?? fallback;
    }

    private AuthorizationExtensionValidationResult ValidatePurposeOfUse(
        string extensionKey,
        object extensionValue,
        HashSet<string>? allowedCodes,
        int? maxCount,
        bool isCommunityResolved,
        string clientId)
    {
        var purposeOfUse = GetPurposeOfUse(extensionKey, extensionValue);

        if (purposeOfUse == null)
        {
            return AuthorizationExtensionValidationResult.Success();
        }

        if (maxCount.HasValue && purposeOfUse.Count > maxCount.Value)
        {
            _logger.LogError(
                "Client {ClientId} extension '{Extension}' purpose_of_use has {Count} entries, maximum allowed is {Max}",
                clientId, extensionKey, purposeOfUse.Count, maxCount.Value);

            return AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                $"Extension '{extensionKey}' purpose_of_use has {purposeOfUse.Count} entries; maximum allowed is {maxCount.Value}");
        }

        if (allowedCodes == null)
        {
            if (isCommunityResolved)
            {
                _logger.LogError(
                    "Client {ClientId} extension '{Extension}' contains purpose_of_use but AllowedPurposeOfUse is not configured for the matched community",
                    clientId, extensionKey);

                return AuthorizationExtensionValidationResult.Failure(
                    "server_error",
                    $"AllowedPurposeOfUse is not configured for the matched community; extension '{extensionKey}' cannot be validated");
            }

            return AuthorizationExtensionValidationResult.Success();
        }

        foreach (var code in purposeOfUse)
        {
            if (!allowedCodes.Contains(code))
            {
                _logger.LogError(
                    "Client {ClientId} extension '{Extension}' contains disallowed purpose_of_use code '{Code}'",
                    clientId, extensionKey, code);

                return AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    $"Extension '{extensionKey}' contains disallowed purpose_of_use code '{code}'");
            }
        }

        return AuthorizationExtensionValidationResult.Success();
    }

    private static ICollection<string>? GetPurposeOfUse(string key, object value)
    {
        if (value is IAuthorizationExtensionObject extensionObject)
        {
            return extensionObject.GetPurposeOfUse();
        }

        return null;
    }

    private static List<string> ValidateExtensionObject(string key, object value)
    {
        if (value is IAuthorizationExtensionObject extensionObject)
        {
            return extensionObject.Validate();
        }

        return [];
    }

    private class ResolvedSettings
    {
        public bool IsCommunityResolved { get; init; }
        public string? CommunityName { get; init; }
        public HashSet<string>? RequiredExtensions { get; init; }
        public HashSet<string>? AllowedPurposeOfUse { get; init; }
        public int? MaxPurposeOfUseCount { get; init; }
    }
}

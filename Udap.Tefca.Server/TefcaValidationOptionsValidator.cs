#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Options;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates <see cref="TefcaValidationOptions"/> at startup. Registered by
/// <see cref="ServiceCollectionExtensions.AddUdapTefcaValidation(Microsoft.Extensions.DependencyInjection.IServiceCollection, Action{TefcaValidationOptions})"/>
/// with <c>ValidateOnStart</c>, so a misconfiguration stops the host instead of failing requests.
/// </summary>
public class TefcaValidationOptionsValidator : IValidateOptions<TefcaValidationOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, TefcaValidationOptions options)
    {
        if (options.ExchangePurposeLocation == ExchangePurposeLocation.QueryParameter
            && string.IsNullOrWhiteSpace(options.ExchangePurposeQueryParameter))
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(TefcaValidationOptions)}.{nameof(TefcaValidationOptions.ExchangePurposeQueryParameter)} " +
                $"must be set when {nameof(TefcaValidationOptions.ExchangePurposeLocation)} is " +
                $"{nameof(ExchangePurposeLocation.QueryParameter)}. There is no default name; configure the " +
                "query parameter your community's client SAN uses.");
        }

        if (!Enum.IsDefined(options.ExchangePurposeLocation))
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(TefcaValidationOptions)}.{nameof(TefcaValidationOptions.ExchangePurposeLocation)} " +
                $"has an unknown value '{options.ExchangePurposeLocation}'.");
        }

        return ValidateOptionsResult.Success;
    }
}

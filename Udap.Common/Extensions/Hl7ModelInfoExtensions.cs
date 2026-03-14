#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Hl7.Fhir.Model;


namespace Udap.Common.Extensions;

/// <summary>
/// Extension methods for building HL7 FHIR SMART-on-FHIR scope strings from the FHIR model info.
/// Generates scopes in both v1 (e.g., <c>system/Patient.read</c>) and v2 (e.g., <c>system/Patient.rs</c>) formats
/// based on the FHIR resource types available in the model.
/// </summary>
public static class Hl7ModelInfoExtensions
{
    /// <summary>
    /// Builds both SMART v1 and v2 scopes for the specified prefixes and all supported FHIR resource types.
    /// </summary>
    /// <param name="prefixes">The scope prefixes (e.g., <c>system</c>, <c>user</c>, <c>patient</c>).</param>
    /// <param name="specification">An optional filter to include only specific resource types.</param>
    /// <param name="v1Suffix">The v1 scope suffix. Defaults to <c>read</c>.</param>
    /// <param name="v2Suffix">The v2 scope suffix. Defaults to <c>rs</c>, which expands to all combinations.</param>
    /// <returns>A set of all generated scope strings.</returns>
    public static HashSet<string> BuildHl7FhirV1AndV2Scopes(
        List<string> prefixes,
        Func<string, bool>? specification = null,
        string v1Suffix = "read",
        string v2Suffix = "rs")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV1Scopes(prefix, specification, v1Suffix, scopes);
            BuildHl7FhirV2Scopes(prefix, specification, v2Suffix, scopes);
        }

        return scopes;
    }

    /// <summary>
    /// Builds both SMART v1 and v2 scopes for a single prefix and all supported FHIR resource types.
    /// </summary>
    /// <param name="prefix">The scope prefix (e.g., <c>system</c>).</param>
    /// <param name="specification">An optional filter to include only specific resource types.</param>
    /// <param name="v1Suffix">The v1 scope suffix. Defaults to <c>read</c>.</param>
    /// <param name="v2Suffix">The v2 scope suffix. Defaults to <c>rs</c>.</param>
    /// <param name="scopes">An optional existing set to add scopes to. A new set is created if <c>null</c>.</param>
    /// <returns>The set of generated scope strings.</returns>
    public static HashSet<string> BuildHl7FhirV1AndV2Scopes(
        string prefix,
        Func<string, bool>? specification = null,
        string v1Suffix = "read",
        string v2Suffix = "rs",
        HashSet<string>? scopes = null)
    {
        scopes ??= [];

        BuildHl7FhirV1Scopes(prefix, specification, v1Suffix, scopes);
        BuildHl7FhirV2Scopes(prefix, specification, v2Suffix, scopes);

        return scopes;
    }

    /// <summary>
    /// Builds SMART v2 scopes for the specified prefixes. V2 scopes use suffix combinations
    /// (e.g., <c>rs</c> expands to <c>r</c>, <c>s</c>, <c>rs</c>).
    /// </summary>
    /// <param name="prefixes">The scope prefixes (e.g., <c>system</c>, <c>user</c>).</param>
    /// <param name="specification">An optional filter to include only specific resource types.</param>
    /// <param name="suffix">The v2 scope suffix to expand. Defaults to <c>rs</c>.</param>
    /// <returns>A set of all generated v2 scope strings.</returns>
    public static HashSet<string> BuildHl7FhirV2Scopes(List<string> prefixes, Func<string, bool>? specification = null, string suffix = "rs")
    {
        var scopes = new HashSet<string>();
        var parameters = suffix.ToList();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV2Scopes(prefix, specification, suffix, scopes);
        }

        return scopes;
    }

    /// <summary>
    /// Builds SMART v2 scopes for a single prefix. V2 scopes use suffix combinations
    /// (e.g., <c>rs</c> expands to <c>r</c>, <c>s</c>, <c>rs</c>) and include a wildcard scope.
    /// </summary>
    /// <param name="prefix">The scope prefix (e.g., <c>system</c>).</param>
    /// <param name="specification">An optional filter to include only specific resource types.</param>
    /// <param name="suffix">The v2 scope suffix to expand. Defaults to <c>rs</c>.</param>
    /// <param name="scopes">An optional existing set to add scopes to. A new set is created if <c>null</c>.</param>
    /// <returns>The set of generated v2 scope strings.</returns>
    public static HashSet<string> BuildHl7FhirV2Scopes(
        string prefix,
        Func<string, bool>? specification = null,
        string suffix = "rs",
        HashSet<string>? scopes = null)
    {
        scopes ??= [];
        specification ??= r => true;
        var parameters = ScopeExtensions.GenerateCombinations(suffix);

        foreach (var parameter in parameters)
        {
            foreach (var resName in ModelInfo.SupportedResources.Where(specification))
            {
                scopes.Add($"{prefix}/{resName}.{parameter}");
            }

            scopes.Add($"{prefix}/*.{parameter}");
        }

        return scopes;
    }

    /// <summary>
    /// Builds SMART v1 scopes for the specified prefixes. V1 scopes use a single suffix
    /// (e.g., <c>system/Patient.read</c>).
    /// </summary>
    /// <param name="prefixes">The scope prefixes (e.g., <c>system</c>, <c>user</c>).</param>
    /// <param name="specification">An optional filter to include only specific resource types.</param>
    /// <param name="suffix">The v1 scope suffix. Defaults to <c>read</c>.</param>
    /// <returns>A set of all generated v1 scope strings.</returns>
    public static HashSet<string> BuildHl7FhirV1Scopes(List<string> prefixes, Func<string, bool>? specification = null, string suffix = "read")
    {
        var scopes = new HashSet<string>();

        foreach (var prefix in prefixes)
        {
            BuildHl7FhirV1Scopes(prefix, specification, suffix, scopes);
        }

        return scopes;
    }

    /// <summary>
    /// Builds SMART v1 scopes for a single prefix and all supported FHIR resource types,
    /// including a wildcard scope (e.g., <c>system/*.read</c>).
    /// </summary>
    /// <param name="prefix">The scope prefix (e.g., <c>system</c>).</param>
    /// <param name="specification">An optional filter to include only specific resource types.</param>
    /// <param name="suffix">The v1 scope suffix. Defaults to <c>read</c>.</param>
    /// <param name="scopes">An optional existing set to add scopes to. A new set is created if <c>null</c>.</param>
    /// <returns>The set of generated v1 scope strings.</returns>
    public static HashSet<string> BuildHl7FhirV1Scopes(
        string prefix,
        Func<string, bool>? specification = null,
        string suffix = "read",
        HashSet<string>? scopes = null)
    {
        scopes ??= [];
        specification ??= r => true;

        foreach (var resName in ModelInfo.SupportedResources.Where(specification))
        {
            scopes.Add($"{prefix}/{resName}.{suffix}");
        }

        scopes.Add($"{prefix}/*.{suffix}");

        return scopes;
    }
}

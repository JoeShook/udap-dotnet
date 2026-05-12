#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigil.Common.Data.Entities;

namespace Sigil.Common.Validators;

public class IssuanceWarning
{
    public string Category { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public class IssuanceValidator
{
    public List<IssuanceWarning> CompareTemplateUrls(
        List<string> originalCdpUrls,
        List<string> originalAiaUrls,
        List<string> templateCdpUrls,
        List<string> templateAiaUrls)
    {
        var warnings = new List<IssuanceWarning>();
        var comparer = StringComparer.OrdinalIgnoreCase;

        var oldCdp = new HashSet<string>(originalCdpUrls, comparer);
        var oldAia = new HashSet<string>(originalAiaUrls, comparer);
        var newCdp = new HashSet<string>(templateCdpUrls, comparer);
        var newAia = new HashSet<string>(templateAiaUrls, comparer);

        foreach (var url in oldCdp.Where(u => !newCdp.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "CDP", Message = $"CDP removed: {url}" });
        foreach (var url in newCdp.Where(u => !oldCdp.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "CDP", Message = $"CDP added: {url}" });
        foreach (var url in oldAia.Where(u => !newAia.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "AIA", Message = $"AIA removed: {url}" });
        foreach (var url in newAia.Where(u => !oldAia.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "AIA", Message = $"AIA added: {url}" });

        return warnings;
    }

    public List<string> ExpandUrlTemplates(
        CertificateTemplate template,
        List<string> communityBaseUrls,
        string? issuingCaName)
    {
        var cdpTemplate = template.CdpUrlTemplate;
        if (template.IncludeCdp && string.IsNullOrWhiteSpace(cdpTemplate))
            cdpTemplate = "{BaseUrl}/crls/{CAName}.crl";

        var aiaTemplate = template.AiaUrlTemplate;
        if (template.IncludeAia && string.IsNullOrWhiteSpace(aiaTemplate))
            aiaTemplate = "{BaseUrl}/certs/{CAName}.cer";

        var result = new List<string>();
        result.AddRange(ExpandTemplate(cdpTemplate, communityBaseUrls, issuingCaName));
        result.AddRange(ExpandTemplate(aiaTemplate, communityBaseUrls, issuingCaName));
        return result;
    }

    public List<string> ExpandCdpTemplates(
        CertificateTemplate template,
        List<string> communityBaseUrls,
        string? issuingCaName)
    {
        if (!template.IncludeCdp) return new();

        var cdpTemplate = template.CdpUrlTemplate;
        if (string.IsNullOrWhiteSpace(cdpTemplate))
            cdpTemplate = "{BaseUrl}/crls/{CAName}.crl";

        return ExpandTemplate(cdpTemplate, communityBaseUrls, issuingCaName);
    }

    public List<string> ExpandAiaTemplates(
        CertificateTemplate template,
        List<string> communityBaseUrls,
        string? issuingCaName)
    {
        if (!template.IncludeAia) return new();

        var aiaTemplate = template.AiaUrlTemplate;
        if (string.IsNullOrWhiteSpace(aiaTemplate))
            aiaTemplate = "{BaseUrl}/certs/{CAName}.cer";

        return ExpandTemplate(aiaTemplate, communityBaseUrls, issuingCaName);
    }

    private static List<string> ExpandTemplate(
        string? template,
        List<string> baseUrls,
        string? caName)
    {
        if (string.IsNullOrWhiteSpace(template)) return new();

        if (baseUrls.Count == 0)
        {
            var result = template;
            if (caName != null)
                result = result.Replace("{CAName}", caName, StringComparison.OrdinalIgnoreCase);
            return string.IsNullOrWhiteSpace(result) ? new() : new() { result };
        }

        var expanded = new List<string>();
        foreach (var baseUrl in baseUrls)
        {
            var result = template
                .Replace("{BaseUrl}", baseUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)
                .Replace("{CAName}", caName ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            expanded.Add(result);
        }

        return expanded;
    }
}

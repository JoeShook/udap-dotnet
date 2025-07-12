using System.Text.Json;
using Hl7.Fhir.Model;

namespace Udap.Proxy.Server.IDIPatientMatch;

public interface IIdiPatientRules
{
    /// <summary>
    /// Validates the patient input for the IDI-Patient profiles.
    /// </summary>
    /// <returns>True if valid, otherwise false. Returns error message if not valid.</returns>
    (bool IsValid, string? Error) ValidatePatientProfile(Patient patient);
}

public class IdiPatientRules : IIdiPatientRules
{
    private static readonly HashSet<string> Iso3166Alpha3Codes;
    private static readonly Dictionary<string, string> StateDriverLicenseOids;

    static IdiPatientRules()
    {
        // Adjust the path as needed for your deployment
        var json = File.ReadAllText("IDIPatientMatch/Packages/iso3166-1-alpha3-codes.json");
        var codes = JsonSerializer.Deserialize<List<string>>(json);
        Iso3166Alpha3Codes = codes != null
            ? new HashSet<string>(codes.Select(c => c.ToUpperInvariant()))
            : new HashSet<string>();

        // Load state driver license OIDs
        var oidsJson = File.ReadAllText("IDIPatientMatch/Packages/state-driver-license-oids.json");
        var oidList = JsonSerializer.Deserialize<List<StateOidEntry>>(oidsJson);
        StateDriverLicenseOids = oidList != null
            ? oidList.ToDictionary(
                e => e.Oid,
                e => e.State,
                StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public (bool IsValid, string? Error) ValidatePatientProfile(Patient patient)
    {
        // Validate PPN (passport) identifiers for valid country code
        if (patient.Identifier != null)
        {
            foreach (var id in patient.Identifier)
            {
                var code = id.Type?.Coding?.FirstOrDefault()?.Code;

                if (code == "PPN")
                {
                    var countryCode = ExtractPassportCountryCode(id.System ?? id.Value);
                    if (!IsValidIso3166Alpha3CountryCode(countryCode))
                    {
                        return (false, $"Invalid or missing country code '{countryCode ?? "(none)"}' in passport identifier system '{id.System}'.");
                    }
                    if(countryCode != null && id.System == null)
                    {
                        return (false, $"Missing a value for Passport.");
                    }
                }

                // Driver's License validation
                if (code == "DL")
                {
                    if (string.IsNullOrWhiteSpace(id.System))
                    {
                        return (false, "Missing system for Driver's License identifier.");
                    }
                    if (!StateDriverLicenseOids.ContainsKey(id.System))
                    {
                        return (false, $"Invalid or unknown driver's license OID '{id.System}'.");
                    }
                }
            }
        }

        return (true, null);
    }

    // Extracts the country code from a passport identifier system URI, e.g. http://hl7.org/fhir/sid/passport-AUS => AUS
    private static string? ExtractPassportCountryCode(string? system)
    {
        const string prefix = "http://hl7.org/fhir/sid/passport-";
        if (system != null && system.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return system.Substring(prefix.Length).ToUpperInvariant();
        }
        return null;
    }
    
    private static bool IsValidIso3166Alpha3CountryCode(string? code)
    {
        return !string.IsNullOrWhiteSpace(code) && Iso3166Alpha3Codes.Contains(code.ToUpperInvariant());
    }

    private class StateOidEntry
    {
        public string State { get; set; } = string.Empty;
        public string Oid { get; set; } = string.Empty;
    }
}
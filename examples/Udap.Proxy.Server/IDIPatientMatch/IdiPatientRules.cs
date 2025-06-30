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

    static IdiPatientRules()
    {
        // Adjust the path as needed for your deployment
        var json = File.ReadAllText("IDIPatientMatch/Packages/iso3166-1-alpha3-codes.json");
        var codes = JsonSerializer.Deserialize<List<string>>(json);
        Iso3166Alpha3Codes = codes != null
            ? new HashSet<string>(codes.Select(c => c.ToUpperInvariant()))
            : new HashSet<string>();
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
            }
        }

        var profiles = patient.Meta?.Profile ?? new List<string>();

        if (profiles.Contains(Constants.IdiPatientProfiles.IdiPatientL0))
        {
            int totalWeight = CalculatePatientWeightedInputL0(patient);
            if (totalWeight < 9)
                return (false, $"IDI-Patient-L0 profile requires weighted input to total 9, but got {totalWeight}.");
            return (true, null);
        }
        else if (profiles.Contains(Constants.IdiPatientProfiles.IdiPatientL1))
        {
            int totalWeight = CalculatePatientWeightedInputL1(patient);
            if (totalWeight < 10)
                return (false, $"IDI-Patient-L1 profile requires weighted input to be at least 10, but got {totalWeight}.");
            return (true, null);
        }
        else if (profiles.Contains(Constants.IdiPatientProfiles.IdiPatientL2))
        {
            int totalWeight = CalculatePatientWeightedInputL2(patient);
            if (totalWeight < 10)
                return (false, $"IDI-Patient-L2 profile requires weighted input to be at least 10, but got {totalWeight}.");
            return (true, null);
        }

        // If not an IDI-Patient profile, no validation required
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

    // L0 rules (already implemented)
    public static int CalculatePatientWeightedInputL0(Patient patient)
    {
        return CalculatePatientWeightedInput(patient);
    }

    // L1 rules (currently same as L0, but can be customized)
    public static int CalculatePatientWeightedInputL1(Patient patient)
    {
        return CalculatePatientWeightedInput(patient);
    }

    // L2 rules (currently same as L0, but can be customized)
    public static int CalculatePatientWeightedInputL2(Patient patient)
    {
        return CalculatePatientWeightedInput(patient);
    }

    // Shared weighting logic
    public static int CalculatePatientWeightedInput(Patient patient)
    {
        int total = 0;

        // 5: Passport Number (PPN) and issuing country, Driver’s License Number (DL) or other State ID Number and (in either case) Issuing US State or Territory, or Digital Identifier is weighted 5.
        // Others are weighted 4.
        // (max weight of 10 for this category, even if multiple ID Numbers included)
        int id4Count = 0;
        int id5Count = 0;

        if (patient.Identifier != null)
        {
            foreach (var id in patient.Identifier)
            {
                var code = id.Type?.Coding?.FirstOrDefault()?.Code;
                if ((code == "PPN" || code == "DL" || code == "HL7Identifier") && !string.IsNullOrWhiteSpace(id.Value))
                {
                    id5Count++;
                }
                else
                {
                    id4Count++;
                }
            }
        }
        int id4Weight = Math.Min(id4Count * 4, 10);
        int id5Weight = Math.Min(id5Count * 5, 10);
        total += id5Weight + id4Weight;

        // 4: Address, telecom email/phone, other identifier
        int cat4Count = 0;
        if (patient.Address != null && patient.Address.Any(a =>
            (!string.IsNullOrWhiteSpace(a.Line?.FirstOrDefault()) && !string.IsNullOrWhiteSpace(a.PostalCode)) ||
            (!string.IsNullOrWhiteSpace(a.City) && !string.IsNullOrWhiteSpace(a.State))))
            cat4Count++;

        if (patient.Telecom != null && patient.Telecom.Any(c =>
            c.System == ContactPoint.ContactPointSystem.Email && !string.IsNullOrWhiteSpace(c.Value)))
            cat4Count++;
        if (patient.Telecom != null && patient.Telecom.Any(c =>
            c.System == ContactPoint.ContactPointSystem.Phone && !string.IsNullOrWhiteSpace(c.Value)))
            cat4Count++;
        
        int cat4Weight = Math.Min(cat4Count * 4, 5);
        total += cat4Weight;

        // 3: First Name and Last Name
        var name = patient.Name?.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(name?.Given?.FirstOrDefault()) && !string.IsNullOrWhiteSpace(name?.Family))
            total += 3;

        // 2: Date of Birth
        if (!string.IsNullOrWhiteSpace(patient.BirthDate))
            total += 2;

        return total;
    }
}
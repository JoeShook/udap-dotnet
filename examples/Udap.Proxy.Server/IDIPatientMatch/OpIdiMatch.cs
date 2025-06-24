using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Udap.Proxy.Server.IDIPatientMatch;

namespace Udap.Proxy.Server.IDIPatientMatch;

public class OpIdiMatch : IFhirOperation
{
    public string Name => "$idi-match";
    public string Description => "Identity matching operation per Identity Matching IG";

    private readonly HttpClient _httpClient;
    private readonly string _backendUrl;

    public OpIdiMatch(IConfiguration config)
    {
        _backendUrl = config["FhirUrlProxy:Back"] ?? throw new ArgumentNullException("FhirUrlProxy:Back is not configured");
        _httpClient = new HttpClient();
    }

    public OperationDefinition GetDefinition()
    {
        return new OperationDefinition
        {
            Name = "$idi-match",
            Kind = OperationDefinition.OperationKind.Operation,
            System = false,
            Type = true,
            Instance = false,
            Parameter = new List<OperationDefinition.ParameterComponent>
            {
                new OperationDefinition.ParameterComponent
                {
                    Name = "resource",
                    Use = OperationParameterUse.In,
                    Min = 1,
                    Max = "1",
                    Type = FHIRAllTypes.Patient,
                    Documentation = "A Patient resource that is being requested in the match operation. The requester must use one of the IDI Patient profiles for the resource in their submission."
                },
                new OperationDefinition.ParameterComponent
                {
                    Name = "return",
                    Use = OperationParameterUse.Out,
                    Min = 1,
                    Max = "1",
                    Type = FHIRAllTypes.Bundle,
                    Documentation = "When successful, a Bundle resource containing Patient resources of a high confidence match is returned to the requestor. In addition, an Organization resource of the responding entity will be included in the Bundle for error reporting purposes. When the responding server is unable to return a match, a response of 'No Match Found' will be returned."
                }
            }
        };
    }

    public async Task<Resource> ExecuteAsync(OperationContext context, CancellationToken cancellationToken)
    {
        var parameters = context.Parameters;
        var inputPatient = (Patient)parameters.Parameter.FirstOrDefault(p => p.Name == "resource")?.Resource;

        if (inputPatient == null)
            throw new InvalidOperationException("Missing input patient in parameters");

        // Validate the profile (e.g., IDI-Patient)
        var profile = inputPatient.Meta?.Profile?.FirstOrDefault();
        if (profile != "http://example.com/fhir/StructureDefinition/IDI-Patient")
            throw new InvalidOperationException("Input patient must conform to IDI-Patient profile");

        // Build search query and execute
        var query = BuildSearchQuery(inputPatient);
        var searchUrl = $"{_backendUrl}/Patient?{query}";
        var response = await _httpClient.GetAsync(searchUrl, cancellationToken);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var bundle = new FhirJsonParser().Parse<Bundle>(json);

        // Score candidates
        foreach (var entry in bundle.Entry)
        {
            var candidate = (Patient)entry.Resource;
            var score = CalculateScore(inputPatient, candidate);
            entry.Search = new Bundle.SearchComponent { Score = score };
        }

        return bundle;
    }

    private string BuildSearchQuery(Patient patient)
    {
        var family = patient.Name.FirstOrDefault()?.Family;
        var birthdate = patient.BirthDate;
        var identifier = patient.Identifier.FirstOrDefault()?.Value;
        var queryParams = new List<string>();
        if (!string.IsNullOrEmpty(family)) queryParams.Add($"family={Uri.EscapeDataString(family)}");
        if (!string.IsNullOrEmpty(birthdate)) queryParams.Add($"birthdate={birthdate}");
        if (!string.IsNullOrEmpty(identifier)) queryParams.Add($"identifier={identifier}");
        return string.Join("&", queryParams);
    }

    private decimal CalculateScore(Patient input, Patient candidate)
    {
        bool familyMatch = input.Name.FirstOrDefault()?.Family == candidate.Name.FirstOrDefault()?.Family;
        bool birthdateMatch = input.BirthDate == candidate.BirthDate;
        bool identifierMatch = input.Identifier.FirstOrDefault()?.Value == candidate.Identifier.FirstOrDefault()?.Value;

        if (familyMatch && birthdateMatch && identifierMatch) return 1.0m;
        if (familyMatch && birthdateMatch) return 0.7m;
        return 0.0m;
    }
}
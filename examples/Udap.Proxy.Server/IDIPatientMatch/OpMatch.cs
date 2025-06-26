using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using System.Collections.ObjectModel;
using System.Net.Http.Headers;
using Udap.Proxy.Server.Services;

namespace Udap.Proxy.Server.IDIPatientMatch;

public class OpMatch : IFhirOperation
{
    private readonly IConfiguration _config;
    private readonly IAccessTokenService _accessTokenService;
    public string Name => "$match";
    public string Description => "Standard patient matching operation";

    private readonly HttpClient _httpClient;
    private readonly string _backendUrl;

    public OpMatch(IConfiguration config, IAccessTokenService accessTokenService)
    {
        _config = config;
        _accessTokenService = accessTokenService;
        _backendUrl = config["FhirUrlProxy:Back"] ?? throw new ArgumentNullException("FhirUrlProxy:Back is not configured");
        _httpClient = new HttpClient();

    }

    public OperationDefinition GetDefinition()
    {
        return new OperationDefinition
        {
            Name = "$match",
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
                    Type = FHIRAllTypes.Patient
                },
                new OperationDefinition.ParameterComponent
                {
                    Name = "count",
                    Use = OperationParameterUse.In,
                    Min = 0,
                    Max = "1",
                    Type = FHIRAllTypes.Integer
                },
                new OperationDefinition.ParameterComponent
                {
                    Name = "onlyCertainMatches",
                    Use = OperationParameterUse.In,
                    Min = 0,
                    Max = "1",
                    Type = FHIRAllTypes.Boolean
                },
                new OperationDefinition.ParameterComponent
                {
                    Name = "return",
                    Use = OperationParameterUse.Out,
                    Min = 1,
                    Max = "1",
                    Type = FHIRAllTypes.Bundle,
                    Documentation = "A bundle containing matched patients with scores"
                }
            }
        };
    }

    public async Task<Resource> ExecuteAsync(OperationContext context, CancellationToken cancellationToken)
    {
        var parameters = context.Parameters;
        var inputPatient = (Patient)parameters.Parameter.FirstOrDefault(p => p.Name == "resource")?.Resource;

        if (inputPatient == null)
        {
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Required,
                        Diagnostics = "Missing input patient in parameters"
                    }
                }
            };
        }


        // Build a search query based on patient demographics
        var query = BuildSearchQuery(inputPatient);

        // Search the backend FHIR server
        var searchUrl = $"{_backendUrl}/Patient?{query}";
        var dict = new Dictionary<string, string>();
        dict.TryAdd("GCPKeyResolve", "gcp_joe_key_location");
        var resolveAccessToken = await _accessTokenService.ResolveAccessTokenAsync(dict, cancellationToken);
        var request = new HttpRequestMessage(HttpMethod.Get, searchUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resolveAccessToken);
        var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var bundle = new FhirJsonParser().Parse<Bundle>(json);

        // Score the candidates
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
        var queryParams = new List<string>();
        if (!string.IsNullOrEmpty(family)) queryParams.Add($"family={Uri.EscapeDataString(family)}");
        if (!string.IsNullOrEmpty(birthdate)) queryParams.Add($"birthdate={birthdate}");
        return string.Join("&", queryParams);
    }

    private decimal CalculateScore(Patient input, Patient candidate)
    {
        bool familyMatch = input.Name.FirstOrDefault()?.Family == candidate.Name.FirstOrDefault()?.Family;
        bool birthdateMatch = input.BirthDate == candidate.BirthDate;

        if (familyMatch && birthdateMatch) return 1.0m;
        if (familyMatch) return 0.5m;
        return 0.0m;
    }
}
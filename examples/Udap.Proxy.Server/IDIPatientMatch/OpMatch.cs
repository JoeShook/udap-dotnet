using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using System.Net.Http.Headers;
using Google.Apis.Util;
using Udap.Proxy.Server.Services;

namespace Udap.Proxy.Server.IDIPatientMatch;

public class OpMatch : IFhirOperation
{
    private readonly IAccessTokenService _accessTokenService;
    private readonly ILogger<OpMatch> _logger;
    public string Name => "$match";
    public string Description => "Standard patient matching operation";
    private readonly HttpClient _httpClient;
    private readonly string _backendUrl;
    private readonly IIdiPatientRules _idiPatientRules;

    public OpMatch(
        IConfiguration config,
        IAccessTokenService accessTokenService,
        HttpClient httpClient,
        ILogger<OpMatch> logger,
        IIdiPatientRules idiPatientRules)
    {
        config.ThrowIfNull(nameof(config));
        _accessTokenService = accessTokenService ?? throw new ArgumentNullException(nameof(accessTokenService));
        _backendUrl = config["FhirUrlProxy:Back"] ?? throw new ArgumentNullException("FhirUrlProxy:Back is not configured");
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _idiPatientRules = idiPatientRules ?? throw new ArgumentNullException(nameof(idiPatientRules));
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
        var inputPatient = parameters.Parameter.FirstOrDefault(p => p.Name == "resource")?.Resource;
        var patient = inputPatient as Patient;

        if (patient == null)
        {
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Required,
                        Diagnostics = "Missing input named resource in parameters"
                    }
                }
            };
        }

        // Validate IDI-Patient profile rules if present
        var (isValid, error) = _idiPatientRules.ValidatePatientProfile(patient);
        if (!isValid)
        {
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Invalid,
                        Diagnostics = error
                    }
                }
            };
        }

        // Build a search query based on patient demographics
        var query = BuildSearchQuery(patient);

        // Search the backend FHIR server
        var searchUrl = $"{_backendUrl}/Patient?{query}";
        try
        {
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
                var score = CalculateScore(patient, candidate);
                entry.Search = new Bundle.SearchComponent { Score = score };
            }

            return bundle;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error connecting to backend FHIR server");
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Exception,
                        Diagnostics = "An error occurred while connecting to the backend FHIR server. Please try again later."
                    }
                }
            };
        }
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
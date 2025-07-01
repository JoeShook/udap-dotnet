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
    private readonly IPatientMatchInValidator _patientMatchInValidator;

    public OpMatch(
        IConfiguration config,
        IAccessTokenService accessTokenService,
        HttpClient httpClient,
        ILogger<OpMatch> logger,
        IPatientMatchInValidator patientMatchInValidator)
    {
        config.ThrowIfNull(nameof(config));
        _accessTokenService = accessTokenService ?? throw new ArgumentNullException(nameof(accessTokenService));
        _backendUrl = config["FhirUrlProxy:Back"] ?? throw new ArgumentNullException("FhirUrlProxy:Back is not configured");
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _patientMatchInValidator = patientMatchInValidator ?? throw new ArgumentNullException(nameof(patientMatchInValidator));
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
        try
        {
            var parameters = context.Parameters;
            var validationOutcome = await _patientMatchInValidator.Validate(parameters);
            if (validationOutcome != null)
            {
                return validationOutcome;
            }

            var inputPatient = parameters.Parameter.FirstOrDefault(p => p.Name == "resource")?.Resource;
            var patient = inputPatient as Patient;

            var query = BuildSearchQuery(patient);
            var searchUrl = $"{_backendUrl}/Patient?{query}";

            var resolveAccessToken = await _accessTokenService.ResolveAccessTokenAsync(
                context.HttpContext.RequestServices.GetRequiredService<ILogger<OpMatch>>(),
                cancellationToken: cancellationToken);
            var request = new HttpRequestMessage(HttpMethod.Get, searchUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resolveAccessToken);
            var response = await _httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var bundle = new FhirJsonParser().Parse<Bundle>(json);

            // Score candidates
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
            _logger.LogError(ex, "OpIdiMatch unknown error");
            return new OperationOutcome
            {
                Issue =
                [
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Exception,
                        Diagnostics =
                            "An error occurred while connecting to the backend FHIR server. Please try again later."
                    }
                ]
            };
        }
    }

    private string BuildSearchQuery(Patient patient)
    {
        var queryParams = new List<string>();

        // Collect all unique family names and given names from all HumanName entries
        var familyNames = patient.Name?
            .Where(n => !string.IsNullOrWhiteSpace(n.Family))
            .Select(n => n.Family)
            .Distinct()
            .ToList() ?? new List<string>();

        var givenNames = patient.Name?
            .SelectMany(n => n.Given ?? Enumerable.Empty<string>())
            .Where(g => !string.IsNullOrWhiteSpace(g))
            .Distinct()
            .ToList() ?? new List<string>();

        foreach (var family in familyNames)
        {
            queryParams.Add($"family={Uri.EscapeDataString(family)}");
        }

        foreach (var given in givenNames)
        {
            queryParams.Add($"given={Uri.EscapeDataString(given)}");
        }

        if (familyNames.Count == 0 && givenNames.Count == 0 && patient.Name != null)
        {
            var textNames = patient.Name
                .Where(n => !string.IsNullOrWhiteSpace(n.Text))
                .Select(n => n.Text)
                .Distinct();

            foreach (var text in textNames)
            {
                queryParams.Add($"name={Uri.EscapeDataString(text)}");
            }
        }

        if (!string.IsNullOrEmpty(patient.BirthDate))
        {
            queryParams.Add($"birthdate={patient.BirthDate}");
        }

        // Support multiple identifiers if present
        if (patient.Identifier != null)
        {
            foreach (var identifier in patient.Identifier)
            {
                if (!string.IsNullOrEmpty(identifier.Value))
                {
                    queryParams.Add($"identifier={Uri.EscapeDataString(identifier.Value)}");
                }
            }
        }

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
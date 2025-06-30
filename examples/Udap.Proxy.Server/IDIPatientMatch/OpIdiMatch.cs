using Google.Apis.Util;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using System.Net.Http.Headers;
using Udap.Proxy.Server.Services;

namespace Udap.Proxy.Server.IDIPatientMatch;

public class OpIdiMatch : IFhirOperation
{
    private readonly IAccessTokenService _accessTokenService;
    private readonly ILogger<OpIdiMatch> _logger;
    public string Name => "$idi-match";
    public string Description => "Identity matching operation per Identity Matching IG";
    private readonly HttpClient _httpClient;
    private readonly string _backendUrl;
    private readonly IIdiPatientRules _idiPatientRules;
    private readonly IIdiPatientMatchInValidator _idiPatientMatchInValidator;

    public OpIdiMatch(
        IConfiguration config,
        IAccessTokenService accessTokenService,
        HttpClient httpClient,
        ILogger<OpIdiMatch> logger,
        IIdiPatientRules idiPatientRules,
        IIdiPatientMatchInValidator idiPatientMatchInValidator)
    {
        config.ThrowIfNull(nameof(config));
        _accessTokenService = accessTokenService ?? throw new ArgumentNullException(nameof(accessTokenService));
        _backendUrl = config["FhirUrlProxy:Back"] ?? throw new ArgumentNullException("FhirUrlProxy:Back is not configured");
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _idiPatientRules = idiPatientRules ?? throw new ArgumentNullException(nameof(idiPatientRules));
        _idiPatientMatchInValidator = idiPatientMatchInValidator ?? throw new ArgumentNullException(nameof(idiPatientMatchInValidator));
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
        // Validate profile:
        var parameters = context.Parameters;
        var validationOutcome = await _idiPatientMatchInValidator.Validate(parameters);
        if (validationOutcome != null)
        {
            return validationOutcome;
        }

        var inputPatient = parameters.Parameter.FirstOrDefault(p => p.Name == "patient")?.Resource;
        var patient = inputPatient as Patient;


        // Build search query and execute
        var query = BuildSearchQuery(patient);
        var searchUrl = $"{_backendUrl}/Patient?{query}";
        _logger.LogDebug(searchUrl);
        try
        {
            var dict = new Dictionary<string, string>();
            dict.TryAdd("GCPKeyResolve", "gcp_joe_key_location");
            var resolveAccessToken = await _accessTokenService.ResolveAccessTokenAsync(
                dict,
                context.HttpContext.RequestServices.GetRequiredService<ILogger<OpIdiMatch>>(),
                cancellationToken: cancellationToken);
            var request = new HttpRequestMessage(HttpMethod.Get, searchUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", resolveAccessToken);
            var response = await _httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
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
        bool identifierMatch = input.Identifier.FirstOrDefault()?.Value == candidate.Identifier.FirstOrDefault()?.Value;

        if (familyMatch && birthdateMatch && identifierMatch) return 1.0m;
        if (familyMatch && birthdateMatch) return 0.7m;
        return 0.0m;
    }
}
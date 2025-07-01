using Firely.Fhir.Packages;
using Firely.Fhir.Validation;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Udap.Proxy.Server.IDIPatientMatch;
using Udap.Proxy.Server.Services;
using T = System.Threading.Tasks;

public class OperationIdiMatchFixture
{
    public OpIdiMatch OpIdiMatch { get; }
    public OpMatch OpMatch { get; }
    public HttpClient HttpClient { get; }
    public IAccessTokenService AccessTokenService { get; }
    public IIdiPatientRules IdiPatientRules { get; }
    public IConfiguration Config { get; }
    public IdiPatientMatchInValidator IdiPatientMatchInValidator { get; }
    public PatientMatchInValidator PatientMatchInValidator { get; }
    public ILogger<OpIdiMatch> OpIdiMatchLogger { get; }
    public ILogger<OpMatch> OpMatchLogger { get; }

    public OperationIdiMatchFixture()
    {
        Config = NSubstitute.Substitute.For<IConfiguration>();
        Config["FhirUrlProxy:Back"].Returns("https://example.com/fhir");

        AccessTokenService = NSubstitute.Substitute.For<IAccessTokenService>();
        AccessTokenService
            .ResolveAccessTokenAsync(
                NSubstitute.Arg.Any<ILogger<OpIdiMatch>>(),
                NSubstitute.Arg.Any<CancellationToken>())
            .Returns("dummy-token");

        HttpClient = new HttpClient(new MockHttpMessageHandler());
        OpIdiMatchLogger = Substitute.For<ILogger<OpIdiMatch>>();
        OpMatchLogger = Substitute.For<ILogger<OpMatch>>();

        IAsyncResourceResolver packageSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/Packages/hl7.fhir.r4b.core-4.3.0.tgz");
        var coreSource = new CachedResolver(packageSource);
        var coreSnapshot = new SnapshotSource(coreSource);
        var terminologySource = new LocalTerminologyService(coreSnapshot);
        IAsyncResourceResolver idiSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/Packages/hl7.fhir.us.identity-matching-2.0.0-ballot.tgz");
        var source = new MultiResolver(idiSource, coreSnapshot);
        var settings = new ValidationSettings { ConformanceResourceResolver = source };
        var fhirProfileValidator = new Validator(source, terminologySource, null, settings);

        IdiPatientRules = new IdiPatientRules();       


        IdiPatientMatchInValidator = new IdiPatientMatchInValidator(IdiPatientRules, fhirProfileValidator);
        PatientMatchInValidator = new PatientMatchInValidator(IdiPatientRules, fhirProfileValidator);


        OpIdiMatch = new OpIdiMatch(
            Config,
            AccessTokenService,
            HttpClient,
            OpIdiMatchLogger,
            IdiPatientMatchInValidator);

        OpMatch = new OpMatch(
            Config,
            AccessTokenService,
            HttpClient,
            OpMatchLogger,
            PatientMatchInValidator);
    }

    // Mock HTTP handler to simulate FHIR backend
    private class MockHttpMessageHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage? request, CancellationToken cancellationToken)
            {
            var bundle = new Bundle
            {
                Type = Bundle.BundleType.Searchset,
                Entry = new List<Bundle.EntryComponent>()
            };
            var json = new FhirJsonSerializer().SerializeToString(bundle);
            return T.Task.FromResult(new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/fhir+json")
            });
        }
    }

    public void SetupRequestServices(HttpContext context)
    {
        var serviceProvider = NSubstitute.Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(ILogger<OpIdiMatch>))
            .Returns(OpIdiMatchLogger);

        context.RequestServices = serviceProvider;
    }
}
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
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
    public HttpClient HttpClient { get; }
    public IAccessTokenService AccessTokenService { get; }
    public IIdiPatientRules IdiPatientRules { get; }
    public IConfiguration Config { get; }
    public IIdiPatientMatchInValidator IdiPatientMatchInValidator { get; }
    public ILogger<OpIdiMatch> OpIdiMatchLogger { get; }

    public OperationIdiMatchFixture()
    {
        Config = NSubstitute.Substitute.For<IConfiguration>();
        Config["FhirUrlProxy:Back"].Returns("https://example.com/fhir");

        AccessTokenService = NSubstitute.Substitute.For<IAccessTokenService>();
        AccessTokenService
            .ResolveAccessTokenAsync(
                NSubstitute.Arg.Any<IReadOnlyDictionary<string, string>>(),
                NSubstitute.Arg.Any<ILogger<OpIdiMatch>>(),
                NSubstitute.Arg.Any<CancellationToken>())
            .Returns("dummy-token");

        HttpClient = new HttpClient(new MockHttpMessageHandler());
        OpIdiMatchLogger = NSubstitute.Substitute.For<Microsoft.Extensions.Logging.ILogger<OpIdiMatch>>();

        // Use the real rules and validator
        IdiPatientRules = new IdiPatientRules();
        IdiPatientMatchInValidator = new IdiPatientMatchInValidator(IdiPatientRules);

        OpIdiMatch = new OpIdiMatch(
            Config,
            AccessTokenService,
            HttpClient,
            OpIdiMatchLogger,
            IdiPatientRules,
            IdiPatientMatchInValidator);
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
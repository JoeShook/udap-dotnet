using Hl7.Fhir.Rest;
using Hl7.Fhir.Specification;
using System.Net.Http;


namespace Udap.Client.Rest;

/// <summary>
/// Specialize the FhirClient injecting a url resolver in the implementation of a IBaseUrlProvider
/// </summary>
public class FhirClientWithUrlProvider : FhirClient
{
    public FhirClientWithUrlProvider(IBaseUrlProvider baseUrlProvider, HttpClient httpClient, FhirClientSettings? settings = null, IStructureDefinitionSummaryProvider? provider = null)
         : base(baseUrlProvider.GetBaseUrl(), httpClient, settings, provider)
    {
        var requester = new HttpClientRequester(baseUrlProvider.GetBaseUrl(), Settings, httpClient);
        Requester = requester;
        HttpVersion = requester.Client.DefaultRequestVersion;
        // Expose default request headers to user.
        RequestHeaders = requester.Client.DefaultRequestHeaders;
    }

    public Version HttpVersion { get; }
}

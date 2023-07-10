#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using Udap.Client.Rest;
using UdapEd.Shared.Model;

namespace UdapEd.Server.Services;

public class FhirService
{
    readonly HttpClient _httpClient;
    private readonly FhirClientWithUrlProvider _fhirClient;
    private readonly ILogger<FhirService> _logger;

    public FhirService(HttpClient httpClient, FhirClientWithUrlProvider fhirClient, ILogger<FhirService> logger)
    {
        _httpClient = httpClient;
        _fhirClient = fhirClient;
        _logger = logger;
    }
    
    public async Task<FhirResultModel<List<Patient>>> SearchPatient(PatientSearchModel model)
    {
        var searchParams = new SearchParams();

        if (!string.IsNullOrEmpty(model.Id))
        {
            searchParams.Add("_id", model.Id);
        }

        if (!string.IsNullOrEmpty(model.Identifier))
        {
            searchParams.Add("identifier", model.Identifier);
        }

        if (!string.IsNullOrEmpty(model.Family))
        {
            searchParams.Add("family", model.Family);
        }

        if (!string.IsNullOrEmpty(model.Given))
        {
            searchParams.Add("given", model.Given);
        }

        if (!string.IsNullOrEmpty(model.Name))
        {
            searchParams.Add("name", model.Name);
        }

        if (model.BirthDate.HasValue)
        {
            searchParams.Add("birthdate", model.BirthDate.Value.ToString("yyyy-MM-dd"));
        }


        try
        {
            var bundle = await _fhirClient.SearchAsync<Patient>(searchParams);
            // var bundleJson = await new FhirJsonSerializer().SerializeToStringAsync(bundle);
            // return Ok(bundleJson);
            var patients = bundle.Entry.Select(e => e.Resource as Patient).ToList();
            return new FhirResultModel<List<Patient>>(patients, HttpStatusCode.OK, _fhirClient.HttpVersion);

        }
        catch (FhirOperationException ex)
        {
            _logger.LogWarning(ex.Message);

            if (ex.Status == HttpStatusCode.Unauthorized)
            {
                return new FhirResultModel<List<Patient>>(true);
            }

            if (ex.Outcome != null)
            {
                return new FhirResultModel<List<Patient>>(ex.Outcome, ex.Status, _fhirClient.HttpVersion);
            }

            var operationOutCome = new OperationOutcome()
            {
                ResourceBase = null,
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Diagnostics = "Resource Server Error: " + ex.Message
                    }
                }
            };
               
            return new FhirResultModel<List<Patient>>(operationOutCome, ex.Status, _fhirClient.HttpVersion);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            throw;
        }
    }

    public async Task<FhirResultModel<Bundle>> MatchPatient(string parametersJson)
    {
        var parameters = await new FhirJsonParser().ParseAsync<Parameters>(parametersJson);
        var json = await new FhirJsonSerializer().SerializeToStringAsync(parameters); // removing line feeds
        var jsonMessage = JsonSerializer.Serialize(json); // needs to be json
        var content = new StringContent(jsonMessage, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
        var response = await _httpClient.PostAsync("Fhir/MatchPatient", content);

        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadAsStringAsync();
            var bundle = new FhirJsonParser().Parse<Bundle>(result);
            // var patients = bundle.Entry.Select(e => e.Resource as Patient).ToList();

            return new FhirResultModel<Bundle>(bundle, response.StatusCode, response.Version);
        }
        
        Console.WriteLine(response.StatusCode);
        
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new FhirResultModel<Bundle>(true);
        }

        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            var result = await response.Content.ReadAsStringAsync();

            if (result.Contains(nameof(UriFormatException)))
            {
                var operationOutCome = new OperationOutcome()
                {
                    ResourceBase = null
                };

                return new FhirResultModel<Bundle>(operationOutCome, HttpStatusCode.PreconditionFailed, response.Version);
            }
        }

        //todo constant :: and this whole routine is ugly.  Should move logic upstream to controller
        //This code exists from testing various FHIR servers like MEDITECH.
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            var result = await response.Content.ReadAsStringAsync();
            if (result.Contains("Resource Server Error:"))
            {
                var operationOutCome = new OperationOutcome()
                {
                    ResourceBase = null,
                    Issue = new List<OperationOutcome.IssueComponent>
                    {
                        new OperationOutcome.IssueComponent
                        {
                            Diagnostics = result
                        }
                    }
                };

                return new FhirResultModel<Bundle>(operationOutCome, HttpStatusCode.InternalServerError,
                    response.Version);
            }
        }

        {
            var result = await response.Content.ReadAsStringAsync();
            var operationOutcome = new FhirJsonParser().Parse<OperationOutcome>(result);

            return new FhirResultModel<Bundle>(operationOutcome, response.StatusCode, response.Version);
        }
    }
}
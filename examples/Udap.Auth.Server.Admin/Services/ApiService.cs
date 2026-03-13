using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Udap.Auth.Server.Admin.Mappers;
using Udap.Auth.Server.Admin.ViewModel;

namespace Udap.Auth.Server.Admin.Services
{
    public class ApiService
    {
        public HttpClient HttpClient;

        public ApiService(HttpClient client)
        {
            HttpClient = client;
        }

        public async Task<ICollection<Community>> GetCommunities()
        {
            var jsonResponse = await HttpClient.GetStringAsync("api/community");

            //var response = await HttpClient.GetFromJsonAsync<ICollection<Common.Models.Community>>("api/community");
            var options = new JsonSerializerOptions
            {
                ReferenceHandler = ReferenceHandler.Preserve,
                WriteIndented = true
            };
            var response = JsonSerializer.Deserialize<ICollection<Common.Models.Community>>(jsonResponse, options);


            var communities = response?.ToViewModels() ?? new List<Community>();

            return communities;
        }

        public async Task<ICollection<IntermediateCertificate>?> GetRootCertificates()
        {
            var response = await HttpClient.GetFromJsonAsync<ICollection<Common.Models.Intermediate>>("api/intermediateCertificate");

            var intermediateCertificates = response?.ToViewModels();

            return intermediateCertificates;
        }


        internal async Task<Community> Save(Community communityView)
        {
            var community = communityView.ToModel();


            var response = await HttpClient.PostAsJsonAsync("api/community", community).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                var anchorModel = await response.Content.ReadFromJsonAsync<Common.Models.Community>();
                return anchorModel!.ToViewModel();
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task Update(Community communityView)
        {
            var community = communityView.ToModel();

            var response = await HttpClient.PutAsJsonAsync($"api/community/{community.Id}", community).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return;
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task<bool> DeleteCommunity(long communityId, CancellationToken token = default)
        {
            var response = await HttpClient.DeleteAsync($"/api/community/{communityId}");

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions { WriteIndented = true }, token);

            throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
        }


        internal async Task<Anchor> Save(Anchor anchorView)
        {
            var anchor = anchorView.ToModel();


            var response = await HttpClient.PostAsJsonAsync("api/anchor", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                var anchorModel = await response.Content.ReadFromJsonAsync<Common.Models.Anchor>();
                return anchorModel!.ToViewModel();
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions{WriteIndented = true}));
            }
        }

        public async Task Update(Anchor anchorView)
        {
            var anchor = anchorView.ToModel();

            var response = await HttpClient.PutAsJsonAsync($"api/anchor/{anchor.Id}", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return;
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task<bool> DeleteAnchor(long anchorId, CancellationToken token = default)
        {
            var response = await HttpClient.DeleteAsync($"/api/anchor/{anchorId}");

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions { WriteIndented = true }, token);

            throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
        }


        internal async Task<IntermediateCertificate> Save(IntermediateCertificate intermediateCertificateView)
        {
            var anchor = intermediateCertificateView.ToModel();

            var response = await HttpClient.PostAsJsonAsync("api/intermediateCertificate", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                var anchorModel = await response.Content.ReadFromJsonAsync<Common.Models.Intermediate>();
                return anchorModel!.ToViewModel();
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task Update(IntermediateCertificate intermediateCertificateView)
        {
            var anchor = intermediateCertificateView.ToModel();

            var response = await HttpClient.PutAsJsonAsync($"api/intermediateCertificate/{anchor.Id}", anchor).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return;
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);

                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        public async Task<bool> DeleteIntermediateCertificate(long rootCertificateId, CancellationToken token = default)
        {
            var response = await HttpClient.DeleteAsync($"/api/intermediateCertificate/{rootCertificateId}");

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            // var joe = await response.Content.ReadAsStringAsync();
            var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions { WriteIndented = true }, token);

            throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions { WriteIndented = true }));
        }

    }
}

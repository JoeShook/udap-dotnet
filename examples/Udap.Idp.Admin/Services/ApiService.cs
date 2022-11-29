using System.Text.Json;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Services
{
    public class ApiService
    {
        private readonly HttpClient _httpClient;
        private readonly IMapper _mapper;

        public ApiService(HttpClient client, IMapper mapper)
        {
            _httpClient = client;
            _mapper = mapper;
        }

        public async Task<ICollection<Community>> GetCommunities()
        {
            var response = await _httpClient.GetFromJsonAsync<ICollection<Common.Models.Community>>("api/community");

            var communities = _mapper.Map<ICollection<Community>>(response);

            return communities;
        }

        internal async Task<Anchor> Save(Anchor anchorView)
        {
            var anchor = _mapper.Map<Common.Models.Anchor>(anchorView);
            

            var response = await _httpClient.PostAsJsonAsync("api/anchor", anchor).ConfigureAwait(false);
            
            if (response.IsSuccessStatusCode)
            {
                var anchorModel = await response.Content.ReadFromJsonAsync<Common.Models.Anchor>();
                return _mapper.Map<Anchor>(anchorModel);
            }
            else
            {
                var problemDetails = await response.Content.ReadFromJsonAsync<ProblemDetails>().ConfigureAwait(false);
                
                throw new Exception(JsonSerializer.Serialize(problemDetails, new JsonSerializerOptions{WriteIndented = true}));
            }
        }

        public async Task<bool> Delete(long anchorId, CancellationToken token = default)
        {
            var response = await _httpClient.DeleteAsync($"/api/anchor/{anchorId}");
            
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

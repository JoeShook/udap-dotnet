namespace Udap.Proxy.Server.Services;

public class AccessTokenService : IAccessTokenService
{
    private readonly IConfiguration _configuration;

    public AccessTokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<string?> ResolveAccessTokenAsync(IReadOnlyDictionary<string, string> metadata, CancellationToken cancellationToken = default)
    {
        try
        {
            if (metadata.ContainsKey("AccessToken"))
            {
                return _configuration.GetValue<string>(metadata["AccessToken"]);
            }

            if (metadata.TryGetValue("GCPKeyResolve", out var routeAuthorizationPolicy))
            {
                var path = _configuration.GetValue<string>(routeAuthorizationPolicy);

                if (string.IsNullOrWhiteSpace(path))
                {
                    throw new InvalidOperationException(
                        $"The route metadata '{routeAuthorizationPolicy}' must be set to a valid path.");
                }

                var credentials = new ServiceAccountCredentialCache();
                return await credentials.GetAccessTokenAsync(path, "https://www.googleapis.com/auth/cloud-healthcare");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex); // TODO: Replace with proper logging
        }

        return string.Empty;
    }
}
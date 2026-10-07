using Google.Apis.Auth.OAuth2;

namespace Udap.Proxy.Server.Services;


public class AccessTokenService : IAccessTokenService
{
    private readonly IConfiguration _configuration;

    public AccessTokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<string?> ResolveAccessTokenAsync(
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var googleCredentials = await GoogleCredential.GetApplicationDefaultAsync(cancellationToken);
            var token = await googleCredentials.UnderlyingCredential.GetAccessTokenForRequestAsync(cancellationToken: cancellationToken);
            // Never log the token itself: it is a live Google Cloud credential.
            logger.LogDebug("Backend token acquired from Google application default credentials");
            return token;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed access token access"); 
        }

        return string.Empty;
    }
}
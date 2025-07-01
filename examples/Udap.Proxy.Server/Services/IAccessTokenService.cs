namespace Udap.Proxy.Server.Services;

public interface IAccessTokenService
{
    Task<string?> ResolveAccessTokenAsync(
        ILogger logger, 
        CancellationToken cancellationToken = default);
}
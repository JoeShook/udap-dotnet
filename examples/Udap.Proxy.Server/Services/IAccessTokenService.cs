namespace Udap.Proxy.Server.Services;

public interface IAccessTokenService
{
    Task<string?> ResolveAccessTokenAsync(IReadOnlyDictionary<string, string> metadata,
        ILogger logger, CancellationToken cancellationToken = default);
}
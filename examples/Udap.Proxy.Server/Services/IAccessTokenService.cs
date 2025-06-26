namespace Udap.Proxy.Server.Services;

public interface IAccessTokenService
{
    Task<string?> ResolveAccessTokenAsync(IReadOnlyDictionary<string, string> metadata, CancellationToken cancellationToken = default);
}
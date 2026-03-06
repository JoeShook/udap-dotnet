#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Metadata.Server.Security;

/// <summary>
/// Structured security event logged by <see cref="SecurityEventMiddleware"/>.
/// </summary>
public record SecurityEvent
{
    public SecurityEventType EventType { get; init; }
    public string? Login { get; init; }
    public string? AuthType { get; init; }
    public string? SrcIp { get; init; }
    public int HttpResponse { get; init; }
    public string? Method { get; init; }
    public string? Path { get; init; }
    public string? Query { get; init; }
    public string? AcceptEncoding { get; init; }
    public string? ContentEncoding { get; init; }
}

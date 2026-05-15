#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Udap.Client.Client;
using Udap.Common.Certificates;

namespace Udap.Common.Tests.Client;

public class UdapClientMessageHandlerTests
{
    private readonly ILogger<UdapClient> _logger = Substitute.For<ILogger<UdapClient>>();

    [Fact]
    public async Task SendAsync_NullDiscoResponse_ThrowsSecurityTokenInvalidTypeException()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler("null")
        };

        var client = new HttpClient(handler);

        await Assert.ThrowsAsync<SecurityTokenInvalidTypeException>(
            () => client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap"));
    }

    [Fact]
    public async Task SendAsync_InnerHandlerReturnsFailureStatusCode_Throws()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(HttpStatusCode.InternalServerError)
        };

        var client = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap"));
    }

    [Fact]
    public void TokenError_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        string? captured = null;
        Action<string> listener = msg => captured = msg;

        handler.TokenError += listener;
        handler.TokenError -= listener;

        Assert.Null(captured);
    }

    [Fact]
    public void Untrusted_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Action<X509Certificate2> listener = _ => { };
        handler.Untrusted += listener;
        handler.Untrusted -= listener;
    }

    [Fact]
    public void Problem_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Action<ChainElementInfo> listener = _ => { };
        handler.Problem += listener;
        handler.Problem -= listener;
    }

    [Fact]
    public void Error_EventDelegation_CanSubscribeAndUnsubscribe()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Action<X509Certificate2, Exception> listener = (_, _) => { };
        handler.Error += listener;
        handler.Error -= listener;
    }

    [Fact]
    public void UdapDynamicClientRegistrationDocument_DefaultsToNull()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger);

        Assert.Null(handler.UdapDynamicClientRegistrationDocument);
    }

    [Fact]
    public async Task SendAsync_DiscoError_CallsNotifyTokenError_NoSubscriber()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler("{}")
        };

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SendAsync_DiscoError_CallsNotifyTokenError_WithSubscriber()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler("{}")
        };

        string? capturedError = null;
        handler.TokenError += msg => capturedError = msg;

        var client = new HttpClient(handler);
        await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.NotNull(capturedError);
        Assert.Equal("Unknown Error", capturedError);
    }

    [Fact]
    public async Task SendAsync_DiscoError_TokenErrorSubscriberThrows_IsSwallowed()
    {
        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler("{}")
        };

        handler.TokenError += _ => throw new InvalidOperationException("subscriber boom");

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SendAsync_DiscoOk_EntersValidationBranch()
    {
        var json = """{"HttpStatusCode": 200}""";

        var validator = CreateValidator();
        var handler = new UdapClientMessageHandler(validator, _logger)
        {
            InnerHandler = new FakeInnerHandler(json)
        };

        string? capturedError = null;
        handler.TokenError += msg => capturedError = msg;

        var client = new HttpClient(handler);
        await client.GetAsync("https://fhirlabs.net/fhir/r4/.well-known/udap");

        Assert.NotNull(capturedError);
    }

    private static UdapClientDiscoveryValidator CreateValidator()
    {
        var trustChainValidator = new TrustChainValidator(
            Substitute.For<ILogger<TrustChainValidator>>());

        return new UdapClientDiscoveryValidator(
            trustChainValidator,
            Substitute.For<ILogger<UdapClientDiscoveryValidator>>());
    }

    private class FakeInnerHandler : HttpMessageHandler
    {
        private readonly string? _responseBody;
        private readonly HttpStatusCode _statusCode;

        public FakeInnerHandler(string responseBody)
        {
            _responseBody = responseBody;
            _statusCode = HttpStatusCode.OK;
        }

        public FakeInnerHandler(HttpStatusCode statusCode)
        {
            _responseBody = null;
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_statusCode != HttpStatusCode.OK)
            {
                return Task.FromResult(new HttpResponseMessage(_statusCode));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_responseBody ?? "", Encoding.UTF8, "application/json")
            });
        }
    }
}

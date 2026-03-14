#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Udap.Common.Authentication;

namespace Udap.Common.Tests.Authentication;

public class OAuthTokenResponseTests
{
    [Fact]
    public void Success_WithNoError_ReturnsNullError()
    {
        var json = JsonDocument.Parse("""
        {
            "access_token": "token123",
            "token_type": "bearer",
            "refresh_token": "refresh456",
            "expires_in": "3600"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.Equal("token123", response.AccessToken);
        Assert.Equal("bearer", response.TokenType);
        Assert.Equal("refresh456", response.RefreshToken);
        Assert.Equal("3600", response.ExpiresIn);
        Assert.Null(response.Error);
    }

    [Fact]
    public void Success_WithErrorOnly_ReturnsExceptionWithErrorMessage()
    {
        var json = JsonDocument.Parse("""
        {
            "error": "invalid_grant"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.NotNull(response.Error);
        Assert.IsType<AuthenticationFailureException>(response.Error);
        Assert.Contains("invalid_grant", response.Error.Message);
        Assert.StartsWith("OAuth token endpoint failure: ", response.Error.Message);
        Assert.Equal("invalid_grant", response.Error.Data["error"]);
    }

    [Fact]
    public void Success_WithErrorAndDescription_ReturnsExceptionWithDescription()
    {
        var json = JsonDocument.Parse("""
        {
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.NotNull(response.Error);
        Assert.IsType<AuthenticationFailureException>(response.Error);
        Assert.Contains("invalid_client", response.Error.Message);
        Assert.Contains(";Description=Client authentication failed", response.Error.Message);
        Assert.Equal("invalid_client", response.Error.Data["error"]);
        Assert.Equal("Client authentication failed", response.Error.Data["error_description"]);
    }

    [Fact]
    public void Success_WithErrorAndUri_ReturnsExceptionWithUri()
    {
        var json = JsonDocument.Parse("""
        {
            "error": "invalid_request",
            "error_uri": "https://example.com/errors/invalid_request"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.NotNull(response.Error);
        Assert.IsType<AuthenticationFailureException>(response.Error);
        Assert.Contains("invalid_request", response.Error.Message);
        Assert.Contains(";Uri=https://example.com/errors/invalid_request", response.Error.Message);
        Assert.Equal("invalid_request", response.Error.Data["error"]);
        Assert.Equal("https://example.com/errors/invalid_request", response.Error.Data["error_uri"]);
    }

    [Fact]
    public void Success_WithErrorDescriptionAndUri_ReturnsExceptionWithAll()
    {
        var json = JsonDocument.Parse("""
        {
            "error": "unauthorized_client",
            "error_description": "The client is not authorized",
            "error_uri": "https://example.com/docs/errors"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.NotNull(response.Error);
        Assert.IsType<AuthenticationFailureException>(response.Error);

        var message = response.Error.Message;
        Assert.StartsWith("OAuth token endpoint failure: unauthorized_client", message);
        Assert.Contains(";Description=The client is not authorized", message);
        Assert.Contains(";Uri=https://example.com/docs/errors", message);

        Assert.Equal("unauthorized_client", response.Error.Data["error"]);
        Assert.Equal("The client is not authorized", response.Error.Data["error_description"]);
        Assert.Equal("https://example.com/docs/errors", response.Error.Data["error_uri"]);
    }

    [Fact]
    public void Success_WithErrorAndNullDescription_SetsEmptyDescriptionInData()
    {
        // When error_description is absent, TryGetProperty returns false
        // and errorDescription remains a default JsonElement whose ToString() returns ""
        var json = JsonDocument.Parse("""
        {
            "error": "server_error"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.NotNull(response.Error);
        Assert.DoesNotContain(";Description=", response.Error.Message);
        Assert.DoesNotContain(";Uri=", response.Error.Message);
        Assert.Equal("", response.Error.Data["error_description"]);
        Assert.Equal("", response.Error.Data["error_uri"]);
    }

    [Fact]
    public void Success_WithMissingOptionalFields_ReturnsNullProperties()
    {
        var json = JsonDocument.Parse("""
        {
            "access_token": "token123",
            "token_type": "bearer"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.Equal("token123", response.AccessToken);
        Assert.Equal("bearer", response.TokenType);
        Assert.Null(response.RefreshToken);
        Assert.Null(response.ExpiresIn);
        Assert.Null(response.Error);
    }

    [Fact]
    public void Failed_SetsErrorProperty()
    {
        var exception = new InvalidOperationException("Something went wrong");

        using var response = OAuthTokenResponse.Failed(exception);

        Assert.Same(exception, response.Error);
        Assert.Null(response.AccessToken);
        Assert.Null(response.TokenType);
        Assert.Null(response.RefreshToken);
        Assert.Null(response.ExpiresIn);
        Assert.Null(response.Response);
    }

    [Fact]
    public void Dispose_CleansUpResponse()
    {
        var json = JsonDocument.Parse("""
        {
            "access_token": "token123",
            "token_type": "bearer"
        }
        """);

        var response = OAuthTokenResponse.Success(json);
        Assert.NotNull(response.Response);

        response.Dispose();

        // After dispose, accessing the JsonDocument should throw
        Assert.Throws<ObjectDisposedException>(() => response.Response.RootElement.GetProperty("access_token"));
    }

    [Fact]
    public void Success_WithNullValuedError_ReturnsNullError()
    {
        var json = JsonDocument.Parse("""
        {
            "access_token": "token123",
            "token_type": "bearer",
            "error": null
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.Null(response.Error);
    }

    [Fact]
    public void Success_WithAccessTokenAndError_SetsBothProperties()
    {
        // A response could technically contain both access_token and error
        var json = JsonDocument.Parse("""
        {
            "access_token": "token123",
            "token_type": "bearer",
            "error": "invalid_scope",
            "error_description": "The requested scope is invalid"
        }
        """);

        using var response = OAuthTokenResponse.Success(json);

        Assert.Equal("token123", response.AccessToken);
        Assert.NotNull(response.Error);
        Assert.IsType<AuthenticationFailureException>(response.Error);
        Assert.Contains("invalid_scope", response.Error.Message);
    }

    [Fact]
    public void AuthenticationFailureException_WithMessageAndInnerException_SetsProperties()
    {
        var inner = new InvalidOperationException("inner error");
        var exception = new AuthenticationFailureException("outer message", inner);

        Assert.Equal("outer message", exception.Message);
        Assert.Same(inner, exception.InnerException);
    }
}

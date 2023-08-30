using System.Net;

namespace UdapServer.Tests.Common;

// thanks to Damian Hickey for this awesome sample
// https://github.com/damianh/OwinHttpMessageHandler/blob/master/src/OwinHttpMessageHandler/OwinHttpMessageHandler.cs
public class BrowserHandler : DelegatingHandler
{
    private readonly CookieContainer _cookieContainer = new CookieContainer();

    public bool AllowCookies { get; set; } = true;
    public bool AllowAutoRedirect { get; set; } = true;
    public int ErrorRedirectLimit { get; set; } = 20;
    public int StopRedirectingAfter { get; set; } = Int32.MaxValue;

    public BrowserHandler(HttpMessageHandler next)
        : base(next)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await SendCookiesAsync(request, cancellationToken);

        int redirectCount = 0;

        while (AllowAutoRedirect && 
               (300 <= (int)response.StatusCode && (int)response.StatusCode < 400) &&
               redirectCount < StopRedirectingAfter)
        {
            if (redirectCount >= ErrorRedirectLimit)
            {
                throw new InvalidOperationException($"Too many redirects. Error limit = {redirectCount}");
            }

            var location = response.Headers.Location;
            if (!location!.IsAbsoluteUri)
            {
                location = new Uri(response.RequestMessage?.RequestUri!, location);
            }

            request = new HttpRequestMessage(HttpMethod.Get, location);

            response = await SendCookiesAsync(request, cancellationToken).ConfigureAwait(false);

            redirectCount++;
        }

        return response;
    }

    internal Cookie? GetCookie(string uri, string name)
    {
        return _cookieContainer.GetCookies(new Uri(uri)).FirstOrDefault(x => x.Name == name);
    }

    internal Cookie? GetXsrfCookie(string uri, string name)
    {
        return _cookieContainer.GetCookies(new Uri(uri)).FirstOrDefault(x => x.Name.StartsWith(name));
    }

    internal void RemoveCookie(string uri, string name)
    {
        var cookie = _cookieContainer.GetCookies(new Uri(uri)).FirstOrDefault(x => x.Name == name);
        if (cookie != null)
        {
            cookie.Expired = true;
        }
    }

    protected async Task<HttpResponseMessage> SendCookiesAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (AllowCookies)
        {
            if (request.RequestUri != null)
            {
                string cookieHeader = _cookieContainer.GetCookieHeader(request.RequestUri);
                if (!string.IsNullOrEmpty(cookieHeader))
                {
                    request.Headers.Add("Cookie", cookieHeader);
                }
            }
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (AllowCookies && response.Headers.Contains("Set-Cookie"))
        {
            var responseCookieHeader = string.Join(",", response.Headers.GetValues("Set-Cookie"));
            if (request.RequestUri != null)
            {
                _cookieContainer.SetCookies(request.RequestUri, responseCookieHeader);
            }
        }

        return response;
    }
}
using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using SshBuddy.Tests.Support;
using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

public sealed class DistributionAndAuthorizationTests : IAsyncLifetime
{
    private AppFactory _f = null!;
    private HttpClient _c = null!;

    public async Task InitializeAsync()
    {
        _f = await new AppFactory().InitializeAsync();
        _c = _f.CreateNoRedirectClient();
    }

    public Task DisposeAsync() { _c.Dispose(); _f.Dispose(); return Task.CompletedTask; }

    private async Task AddKey(string label, string key)
    {
        await using var scope = _f.Services.CreateAsyncScope();
        Assert.True((await scope.ServiceProvider.GetRequiredService<KeyService>().AddAsync(label, key, "test")).Succeeded);
    }

    [Fact]
    public async Task Empty_list_is_success_with_empty_text_body_for_anonymous_callers()
    {
        var res = await _c.GetAsync("/api/authorized-keys");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("text/plain", res.Content.Headers.ContentType!.MediaType);
        Assert.Equal("", await res.Content.ReadAsStringAsync());
        Assert.NotNull(res.Headers.ETag);
    }

    [Fact]
    public async Task Serves_active_keys_and_supports_conditional_requests()
    {
        await AddKey("laptop", Fixtures.Ed25519);
        var res = await _c.GetAsync("/api/authorized-keys");
        var body = await res.Content.ReadAsStringAsync();
        Assert.Equal("ssh-ed25519 " + Fixtures.Ed25519Blob + " laptop\n", body);
        var etag = res.Headers.ETag!;

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/authorized-keys");
        req.Headers.IfNoneMatch.Add(etag);
        var notModified = await _c.SendAsync(req);
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);

        await AddKey("another", Fixtures.Ed25519Other);
        var req2 = new HttpRequestMessage(HttpMethod.Get, "/api/authorized-keys");
        req2.Headers.IfNoneMatch.Add(etag);
        Assert.Equal(HttpStatusCode.OK, (await _c.SendAsync(req2)).StatusCode);

        var any = new HttpRequestMessage(HttpMethod.Get, "/api/authorized-keys");
        any.Headers.TryAddWithoutValidation("If-None-Match", "*");
        Assert.Equal(HttpStatusCode.NotModified, (await _c.SendAsync(any)).StatusCode);
    }

    [Fact]
    public async Task Head_on_the_key_list_works_like_get_without_a_body()
    {
        var res = await _c.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/api/authorized-keys"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.NotNull(res.Headers.ETag);
        Assert.Empty(await res.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/keys")]
    [InlineData("/enroll")]
    [InlineData("/audit")]
    public async Task Management_pages_redirect_anonymous_users_to_login(string path)
    {
        var res = await _c.GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.StartsWith("/login", res.Headers.Location!.OriginalString.Replace("http://localhost", ""));
    }

    [Fact]
    public async Task Interactive_circuit_endpoint_is_not_open_to_anonymous_callers()
    {
        var res = await _c.PostAsync("/_blazor/negotiate?negotiateVersion=1", new StringContent(""));
        Assert.NotEqual(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Logout_requires_authentication_and_antiforgery()
    {
        var res = await _c.PostAsync("/account/logout", new FormUrlEncodedContent([]));
        Assert.NotEqual(HttpStatusCode.OK, res.StatusCode);
        Assert.NotEqual("/login", res.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task There_is_no_public_registration()
    {
        foreach (var p in new[] { "/register", "/Account/Register", "/api/register", "/Identity/Account/Register" })
            Assert.NotEqual(HttpStatusCode.OK, (await _c.GetAsync(p)).StatusCode);
    }

    [Fact]
    public async Task Login_page_and_its_assets_load_anonymously()
    {
        var page = await _c.GetAsync("/login");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        var assets = Regex.Matches(html, "(?:href|src)=\"([^\"]+\\.(?:css|js))\"").Select(m => m.Groups[1].Value).ToList();
        Assert.Contains(assets, a => a.Contains("bootstrap"));
        Assert.Contains(assets, a => a.Contains("blazor.web"));
        foreach (var a in assets)
            Assert.Equal(HttpStatusCode.OK, (await _c.GetAsync(a)).StatusCode);
    }

    [Fact]
    public async Task Api_errors_are_not_rewritten_into_html_pages()
    {
        // Enroll with no token: a bodiless 401 would be rewritten into the Blazor not-found page if status pages applied.
        var res = await _c.PostAsync("/api/keys/enroll", new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.NotEqual("text/html", res.Content.Headers.ContentType?.MediaType);
    }

    // ---- login ----
    private async Task<(string Cookie, string Token)> LoginFormTokens()
    {
        var page = await _c.GetAsync("/login");
        var html = await page.Content.ReadAsStringAsync();
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var cookie = page.Headers.GetValues("Set-Cookie").First(c => c.Contains(".AspNetCore.Antiforgery")).Split(';')[0];
        Assert.NotEmpty(token);
        return (cookie, token);
    }

    private async Task<HttpResponseMessage> PostLogin(string email, string password, string? token, string? cookie)
    {
        var fields = new Dictionary<string, string> { ["Email"] = email, ["Password"] = password };
        if (token is not null) fields["__RequestVerificationToken"] = token;
        var req = new HttpRequestMessage(HttpMethod.Post, "/account/login") { Content = new FormUrlEncodedContent(fields) };
        if (cookie is not null) req.Headers.Add("Cookie", cookie);
        return await _c.SendAsync(req);
    }

    [Fact]
    public async Task Login_without_antiforgery_token_is_rejected()
    {
        var res = await PostLogin(AppFactory.AdminEmail, AppFactory.AdminPassword, null, null);
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_is_rejected_and_correct_password_opens_the_management_pages()
    {
        var (cookie, token) = await LoginFormTokens();
        var bad = await PostLogin(AppFactory.AdminEmail, "wrong password here", token, cookie);
        Assert.Equal(HttpStatusCode.Redirect, bad.StatusCode);
        Assert.Equal("/login?error=invalid", bad.Headers.Location!.OriginalString);
        Assert.False(bad.Headers.Contains("Set-Cookie") && bad.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("SshBuddy.Auth")));

        var good = await PostLogin(AppFactory.AdminEmail, AppFactory.AdminPassword, token, cookie);
        Assert.Equal(HttpStatusCode.Redirect, good.StatusCode);
        var auth = good.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("SshBuddy.Auth")).Split(';')[0];

        var keys = new HttpRequestMessage(HttpMethod.Get, "/keys");
        keys.Headers.Add("Cookie", auth);
        Assert.Equal(HttpStatusCode.OK, (await _c.SendAsync(keys)).StatusCode);
    }

    // ---- enrollment ----
    private async Task<string> NewToken()
    {
        await using var scope = _f.Services.CreateAsyncScope();
        return (await scope.ServiceProvider.GetRequiredService<EnrollmentService>().CreateTokenAsync("test")).Token;
    }

    private static HttpRequestMessage Enroll(string? token, string label, string key)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/keys/enroll")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["label"] = label, ["publicKey"] = key }),
        };
        if (token is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return req;
    }

    [Fact]
    public async Task Enrollment_requires_a_valid_bearer_token()
    {
        var none = await _c.SendAsync(Enroll(null, "h", Fixtures.Ed25519));
        Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);
        var bad = await _c.SendAsync(Enroll("sbe_wrong", "h", Fixtures.Ed25519));
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
        // A token in the query string is not accepted.
        var token = await NewToken();
        var req = Enroll(null, "h", Fixtures.Ed25519);
        req.RequestUri = new Uri($"/api/keys/enroll?token={token}", UriKind.Relative);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _c.SendAsync(req)).StatusCode);
    }

    [Fact]
    public async Task Enrollment_succeeds_once_with_a_pub_file_including_its_trailing_newline()
    {
        var token = await NewToken();
        var ok = await _c.SendAsync(Enroll(token, "new-ct", Fixtures.Ed25519 + "\n"));
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        Assert.Contains(Fixtures.Ed25519Fingerprint, await ok.Content.ReadAsStringAsync());

        var again = await _c.SendAsync(Enroll(token, "other", Fixtures.Ed25519Other));
        Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode);

        var list = await (await _c.GetAsync("/api/authorized-keys")).Content.ReadAsStringAsync();
        Assert.Contains(Fixtures.Ed25519Blob, list);
    }

    [Fact]
    public async Task Invalid_and_duplicate_submissions_return_errors_without_burning_the_token()
    {
        var token = await NewToken();
        var priv = await _c.SendAsync(Enroll(token, "h", Fixtures.PrivateKey));
        Assert.Equal(HttpStatusCode.BadRequest, priv.StatusCode);
        Assert.Equal("application/problem+json", priv.Content.Headers.ContentType!.MediaType);

        Assert.Equal(HttpStatusCode.Created, (await _c.SendAsync(Enroll(token, "h", Fixtures.Ed25519))).StatusCode);

        var token2 = await NewToken();
        var dup = await _c.SendAsync(Enroll(token2, "h2", Fixtures.Ed25519));
        Assert.Equal(HttpStatusCode.Conflict, dup.StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _c.SendAsync(Enroll(token2, "h2", Fixtures.Ed25519Other))).StatusCode);
    }

    [Fact]
    public async Task Enrollment_rejects_non_form_bodies()
    {
        var token = await NewToken();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/keys/enroll") { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await _c.SendAsync(req)).StatusCode);
    }

    [Fact]
    public void Displayed_curl_command_keeps_the_token_in_a_header_and_never_in_the_url()
    {
        var cmd = EnrollmentCommand.Build("https://keys.example.com/", "sbe_abc");
        Assert.Contains("\"https://keys.example.com/api/keys/enroll\"", cmd);
        Assert.Contains("--header \"Authorization: Bearer sbe_abc\"", cmd);
        Assert.DoesNotContain("?", cmd);
        Assert.DoesNotContain(" -k", cmd);
        Assert.DoesNotContain("--insecure", cmd);
        Assert.Contains("publicKey@", cmd);
    }
}

public sealed class RateLimitTests
{
    [Fact]
    public async Task Login_attempts_are_rate_limited()
    {
        using var f = await new AppFactory(new() { ["RateLimits:LoginPerMinute"] = "3" }).InitializeAsync();
        using var c = f.CreateNoRedirectClient();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            var r = await c.PostAsync("/account/login", new FormUrlEncodedContent([]));
            codes.Add(r.StatusCode);
        }
        Assert.Equal(HttpStatusCode.BadRequest, codes[0]); // no antiforgery token: reached the handler
        Assert.Equal(2, codes.Count(x => x == HttpStatusCode.TooManyRequests));
    }

    [Fact]
    public async Task Enrollment_attempts_are_rate_limited()
    {
        using var f = await new AppFactory(new() { ["RateLimits:EnrollPerMinute"] = "2" }).InitializeAsync();
        using var c = f.CreateNoRedirectClient();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 4; i++)
            codes.Add((await c.PostAsync("/api/keys/enroll", new FormUrlEncodedContent([]))).StatusCode);
        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests, HttpStatusCode.TooManyRequests], codes);
    }
}

public sealed class HttpsEnforcementTests
{
    [Fact]
    public async Task Api_over_plain_http_is_refused_not_redirected_when_https_is_required()
    {
        using var f = await new AppFactory(new() { ["Security:RequireHttps"] = "true" }).InitializeAsync();
        using var http = f.CreateNoRedirectClient();
        var res = await http.PostAsync("/api/keys/enroll", new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/authorized-keys")).StatusCode);

        using var https = f.CreateNoRedirectClient(new Uri("https://localhost"));
        Assert.Equal(HttpStatusCode.OK, (await https.GetAsync("/api/authorized-keys")).StatusCode);
    }

    [Fact]
    public async Task Ui_over_plain_http_redirects_to_https_when_required()
    {
        using var f = await new AppFactory(new() { ["Security:RequireHttps"] = "true" }).InitializeAsync();
        using var http = f.CreateNoRedirectClient();
        var res = await http.GetAsync("/login");
        Assert.Equal(HttpStatusCode.RedirectKeepVerb, res.StatusCode);
        Assert.StartsWith("https://", res.Headers.Location!.OriginalString);
    }
}

/// <summary>Everything else runs as Development; these cover the Production-only pipeline.</summary>
public sealed class ProductionPipelineTests
{
    [Fact]
    public async Task Https_is_required_by_default_in_production()
    {
        using var f = await new AppFactory(environment: "Production").InitializeAsync();
        using var http = f.CreateNoRedirectClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/authorized-keys")).StatusCode);
        using var https = f.CreateNoRedirectClient(new Uri("https://localhost"));
        Assert.Equal(HttpStatusCode.OK, (await https.GetAsync("/api/authorized-keys")).StatusCode);
    }

    [Fact]
    public async Task Auth_cookie_is_secure_httponly_in_production()
    {
        using var f = await new AppFactory(environment: "Production").InitializeAsync();
        using var c = f.CreateNoRedirectClient(new Uri("https://localhost"));
        var page = await c.GetAsync("/login");
        var html = await page.Content.ReadAsStringAsync();
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var antiforgery = page.Headers.GetValues("Set-Cookie").First(x => x.Contains(".AspNetCore.Antiforgery")).Split(';')[0];

        var req = new HttpRequestMessage(HttpMethod.Post, "/account/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Email"] = AppFactory.AdminEmail, ["Password"] = AppFactory.AdminPassword, ["__RequestVerificationToken"] = token,
            }),
        };
        req.Headers.Add("Cookie", antiforgery);
        var res = await c.SendAsync(req);
        var cookie = res.Headers.GetValues("Set-Cookie").Single(x => x.StartsWith("SshBuddy.Auth"));
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ThrowingFactory : Microsoft.EntityFrameworkCore.IDbContextFactory<SshBuddy.Web.Data.AppDbContext>
    {
        public SshBuddy.Web.Data.AppDbContext CreateDbContext() => throw new InvalidOperationException("boom");
    }

    [Fact]
    public async Task Unhandled_errors_on_api_and_posts_are_problem_json_not_html_while_pages_get_the_error_page()
    {
        using var f = await new AppFactory(environment: "Production", configureServices: services =>
            services.AddSingleton<Microsoft.EntityFrameworkCore.IDbContextFactory<SshBuddy.Web.Data.AppDbContext>>(new ThrowingFactory()))
            .InitializeAsync();
        using var c = f.CreateNoRedirectClient(new Uri("https://localhost"));

        var api = await c.GetAsync("/api/authorized-keys");
        Assert.Equal(HttpStatusCode.InternalServerError, api.StatusCode);
        Assert.Equal("application/problem+json", api.Content.Headers.ContentType!.MediaType);
        Assert.DoesNotContain("boom", await api.Content.ReadAsStringAsync());

        var enroll = await c.PostAsync("/api/keys/enroll", new FormUrlEncodedContent(new Dictionary<string, string> { ["label"] = "x" }));
        Assert.NotEqual("text/html", enroll.Content.Headers.ContentType?.MediaType);
    }
}

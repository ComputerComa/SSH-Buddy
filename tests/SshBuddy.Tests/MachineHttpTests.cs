using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SshBuddy.Tests.Support;
using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

public sealed class MachineHttpTests : IAsyncLifetime
{
    private readonly string _releases = Directory.CreateTempSubdirectory("sshbuddy-rel-").FullName;
    private AppFactory _f = null!;
    private HttpClient _c = null!;
    private string _template = "";

    public async Task InitializeAsync()
    {
        WriteRelease("1.4.0");
        _f = await new AppFactory(new() { ["Agent:ReleaseDirectory"] = _releases }).InitializeAsync();
        _c = _f.CreateNoRedirectClient();
        await using var scope = _f.Services.CreateAsyncScope();
        _template = (await scope.ServiceProvider.GetRequiredService<TemplateCredentialService>().CreateAsync("tpl", "test")).Created!.Token;
    }

    public Task DisposeAsync()
    {
        _c.Dispose(); _f.Dispose();
        Directory.Delete(_releases, true);
        return Task.CompletedTask;
    }

    private void WriteRelease(string version)
    {
        var d = Directory.CreateDirectory(Path.Combine(_releases, version)).FullName;
        var sums = new List<string>();
        foreach (var p in new[] { "linux-amd64", "linux-arm64" })
        {
            var bytes = Encoding.UTF8.GetBytes($"\x7fELF fake {version} {p}");
            File.WriteAllBytes(Path.Combine(d, "ssh-buddy-agent-" + p), bytes);
            sums.Add($"{Convert.ToHexStringLower(SHA256.HashData(bytes))}  ssh-buddy-agent-{p}");
        }
        File.WriteAllLines(Path.Combine(d, "SHA256SUMS"), sums);
    }

    private static string Nonce() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private Task<HttpResponseMessage> Post(string url, string? bearer, object body)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body) };
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return _c.SendAsync(req);
    }

    private async Task<string> EnrollOk(string host, string? nonce = null)
    {
        var r = await Post("/api/machines/enroll", _template, new { fqdn = host, nonce = nonce ?? Nonce(), agentVersion = "1.4.0" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("machineCredential").GetString()!;
    }

    [Fact]
    public async Task Enroll_returns_a_credential_once_and_refuses_a_second_claim_to_the_hostname()
    {
        var cred = await EnrollOk("web1.example.com");
        Assert.StartsWith("sbm_", cred);
        Assert.Equal(HttpStatusCode.NoContent, (await Post("/api/machines/checkin", cred, new { agentVersion = "1.4.0", result = "success", appliedEtag = "\"x\"" })).StatusCode);

        var second = await Post("/api/machines/enroll", _template, new { fqdn = "WEB1.example.com.", nonce = Nonce() });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal("application/problem+json", second.Content.Headers.ContentType!.MediaType);
        Assert.DoesNotContain("sbm_", await second.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_lost_response_case_works_over_http()
    {
        var nonce = Nonce();
        var lost = await EnrollOk("web1.example.com", nonce);
        var retry = await EnrollOk("web1.example.com", nonce);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post("/api/machines/checkin", lost, new { result = "success" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Post("/api/machines/checkin", retry, new { result = "success" })).StatusCode);
    }

    [Fact]
    public async Task Credentials_are_not_interchangeable_between_the_three_kinds_of_access()
    {
        var machine = await EnrollOk("web1.example.com");

        // template credential: cannot report, cannot upload a public key, cannot open the admin UI
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post("/api/machines/checkin", _template, new { result = "success" })).StatusCode);
        var upload = new HttpRequestMessage(HttpMethod.Post, "/api/keys/enroll")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["label"] = "x", ["publicKey"] = Fixtures.Ed25519 }),
        };
        upload.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _template);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _c.SendAsync(upload)).StatusCode);
        foreach (var path in new[] { "/keys", "/machines", "/templates", "/audit" })
        {
            var ui = new HttpRequestMessage(HttpMethod.Get, path);
            ui.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _template);
            var res = await _c.SendAsync(ui);
            Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
            Assert.StartsWith("/login", res.Headers.Location!.OriginalString.Replace("http://localhost", ""));
        }

        // machine credential: cannot enroll machines or upload keys
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post("/api/machines/enroll", machine, new { fqdn = "web2.example.com", nonce = Nonce() })).StatusCode);
        upload = new HttpRequestMessage(HttpMethod.Post, "/api/keys/enroll")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["label"] = "x", ["publicKey"] = Fixtures.Ed25519 }),
        };
        upload.Headers.Authorization = new AuthenticationHeaderValue("Bearer", machine);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _c.SendAsync(upload)).StatusCode);

        // a key-upload token cannot enroll machines
        await using var scope = _f.Services.CreateAsyncScope();
        var keyToken = (await scope.ServiceProvider.GetRequiredService<EnrollmentService>().CreateTokenAsync("test")).Token;
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post("/api/machines/enroll", keyToken, new { fqdn = "web3.example.com", nonce = Nonce() })).StatusCode);
    }

    [Fact]
    public async Task Malformed_requests_get_json_errors_never_html()
    {
        foreach (var (url, bearer) in new[] { ("/api/machines/enroll", _template), ("/api/machines/checkin", "sbm_x") })
        {
            var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent("{not json", Encoding.UTF8, "application/json") };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            var res = await _c.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
            Assert.Equal("application/problem+json", res.Content.Headers.ContentType!.MediaType);
        }
        var bad = await Post("/api/machines/enroll", _template, new { fqdn = "nodomain", nonce = Nonce() });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post("/api/machines/enroll", null, new { fqdn = "a.example.com", nonce = Nonce() })).StatusCode);
    }

    [Fact]
    public async Task Manifest_downloads_and_checksums_agree()
    {
        var json = await (await _c.GetAsync("/api/agent/manifest")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("1.4.0", json.GetProperty("version").GetString());
        var amd = json.GetProperty("binaries").EnumerateArray().Single(b => b.GetProperty("platform").GetString() == "linux-amd64");
        Assert.Equal("amd64", amd.GetProperty("arch").GetString());

        var bytes = await _c.GetByteArrayAsync(amd.GetProperty("path").GetString());
        Assert.Equal(amd.GetProperty("size").GetInt64(), bytes.Length);
        Assert.Equal(amd.GetProperty("sha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(bytes)));

        var text = await _c.GetStringAsync("/api/agent/manifest.txt");
        Assert.Contains($"1.4.0 linux-amd64 {bytes.Length} {amd.GetProperty("sha256").GetString()} /api/agent/download/1.4.0/linux-amd64", text);
    }

    [Theory]
    [InlineData("/api/agent/download/9.9.9/linux-amd64")]
    [InlineData("/api/agent/download/1.4.0/linux-386")]
    [InlineData("/api/agent/download/1.4.0/SHA256SUMS")]
    [InlineData("/api/agent/download/..%2F1.4.0/linux-amd64")]
    [InlineData("/api/agent/download/1.4.0/..%2FSHA256SUMS")]
    public async Task Unknown_or_malicious_download_requests_get_404(string url)
    {
        var res = await _c.GetAsync(url);
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
        Assert.NotEqual("text/html", res.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Agent_endpoints_are_public_but_have_no_release_when_none_is_published()
    {
        using var empty = await new AppFactory(new() { ["Agent:ReleaseDirectory"] = Path.Combine(_releases, "nope") }).InitializeAsync();
        using var c = empty.CreateNoRedirectClient();
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/api/agent/manifest")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/api/agent/manifest.txt")).StatusCode);
    }
}

public sealed class CheckInRateLimitTests
{
    [Fact]
    public async Task A_per_address_ceiling_stops_floods_that_use_a_fresh_bearer_value_every_time()
    {
        using var f = await new AppFactory(new() { ["RateLimits:MachineApiPerIpPerMinute"] = "3", ["RateLimits:CheckInPerMinute"] = "1000" }).InitializeAsync();
        using var c = f.CreateNoRedirectClient();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "/api/machines/checkin") { Content = JsonContent.Create(new { result = "success" }) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "sbm_random" + i);   // every request: a "different machine"
            codes.Add((await c.SendAsync(req)).StatusCode);
        }
        Assert.Equal(2, codes.Count(x => x == HttpStatusCode.TooManyRequests));
        // other endpoints are unaffected by this ceiling
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/authorized-keys")).StatusCode);
    }

    [Fact]
    public async Task Check_ins_are_limited_per_credential_not_per_address()
    {
        using var f = await new AppFactory(new() { ["RateLimits:CheckInPerMinute"] = "2" }).InitializeAsync();
        using var c = f.CreateNoRedirectClient();
        async Task<HttpStatusCode> Report(string cred)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "/api/machines/checkin") { Content = JsonContent.Create(new { result = "success" }) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cred);
            return (await c.SendAsync(req)).StatusCode;
        }

        // every request below comes from the same address (the test server's)
        Assert.Equal(HttpStatusCode.Unauthorized, await Report("sbm_a"));
        Assert.Equal(HttpStatusCode.Unauthorized, await Report("sbm_a"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Report("sbm_a"));
        Assert.Equal(HttpStatusCode.Unauthorized, await Report("sbm_b"));   // another machine is unaffected
    }
}

public class RazorLintTests
{
    // Regression for a real bug: <AlertMessage Message="error" /> passes the literal word "error", so the alert
    // is always visible and never shows the message. Only a browser run catches it at runtime; this catches it early.
    [Fact]
    public void Component_parameters_that_look_like_field_names_are_not_passed_as_string_literals()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "global.json"))) root = root.Parent;
        var components = Path.Combine(root!.FullName, "src", "SshBuddy.Web", "Components");

        var offenders = Directory.EnumerateFiles(components, "*.razor", SearchOption.AllDirectories)
            .SelectMany(f => File.ReadAllLines(f).Select((l, i) => (File: Path.GetFileName(f), Line: i + 1, Text: l)))
            .Where(x => System.Text.RegularExpressions.Regex.IsMatch(x.Text, @"<AlertMessage\s+Message=""(error|info|message|status|result)""", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            .Select(x => $"{x.File}:{x.Line}: {x.Text.Trim()}")
            .ToList();

        Assert.True(offenders.Count == 0, "String literal passed where a field was meant (use Message=\"@name\"):\n" + string.Join('\n', offenders));
    }
}

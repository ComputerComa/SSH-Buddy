using System.Diagnostics;
using Microsoft.Extensions.Options;
using SshBuddy.Tests.Support;
using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

/// <summary>Runs the real client/ssh-buddy-sync with a stub curl first on PATH.</summary>
public sealed class ClientScriptTests : IDisposable
{
    // The stub mimics the two curl features the script relies on: --output FILE and --write-out '%{http_code}'.
    private const string FakeCurl = """
        #!/usr/bin/env bash
        out=""; args=("$@")
        for ((i=0;i<${#args[@]};i++)); do [ "${args[i]}" = "--output" ] && out="${args[i+1]}"; done
        printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
        [ -n "$FAKE_BODY_FILE" ] && cp "$FAKE_BODY_FILE" "$out"
        [ "${FAKE_CURL_EXIT:-0}" != 0 ] && exit "$FAKE_CURL_EXIT"
        printf '%s' "${FAKE_CODE:-200}"
        """;

    private readonly string _dir = Directory.CreateTempSubdirectory("sshbuddy-client-").FullName;
    private string Bin => Path.Combine(_dir, "bin");
    private string TargetDir => Path.Combine(_dir, "authorized_keys.d");
    private string Target => Path.Combine(TargetDir, "root-managed");
    private string CurlLog => Path.Combine(_dir, "curl.log");
    private static readonly string Script = Path.Combine(RepoRoot(), "client", "ssh-buddy-sync");

    public ClientScriptTests()
    {
        Directory.CreateDirectory(Bin);
        Directory.CreateDirectory(TargetDir);
        var curl = Path.Combine(Bin, "curl");
        File.WriteAllText(curl, FakeCurl.Replace("\r\n", "\n") + "\n");
        File.SetUnixFileMode(curl, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string RepoRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "global.json"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private (int Exit, string Output) Run(string? body, string code = "200", int curlExit = 0, string url = "https://keys.example.test/api/authorized-keys", byte[]? rawBody = null)
    {
        var bodyFile = Path.Combine(_dir, "body");
        if (rawBody is not null) File.WriteAllBytes(bodyFile, rawBody);
        else if (body is not null) File.WriteAllText(bodyFile, body);

        var psi = new ProcessStartInfo("bash", [Script])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            Environment =
            {
                ["PATH"] = Bin + ":" + Environment.GetEnvironmentVariable("PATH"),
                ["SSH_BUDDY_URL"] = url,
                ["SSH_BUDDY_TARGET"] = Target,
                ["SSH_BUDDY_OWNER"] = $"{Environment.UserName}",
                ["FAKE_CURL_LOG"] = CurlLog,
                ["FAKE_BODY_FILE"] = body is null && rawBody is null ? "" : bodyFile,
                ["FAKE_CODE"] = code,
                ["FAKE_CURL_EXIT"] = curlExit.ToString(),
            },
        };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, output);
    }

    private static readonly string GoodList =
        "ssh-ed25519 " + Fixtures.Ed25519Blob + " alice@laptop\n" +
        "ssh-rsa " + Fixtures.Rsa3072.Split(' ')[1] + " rsa_key\n";

    private string[] TempFiles() => Directory.GetFiles(TargetDir).Where(f => f != Target).ToArray();

    [Fact]
    public void Installs_a_valid_list_with_644_permissions_and_leaves_no_temp_files()
    {
        var r = Run(GoodList);
        Assert.Equal(0, r.Exit);
        Assert.Equal(GoodList, File.ReadAllText(Target));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead, File.GetUnixFileMode(Target));
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void Does_not_touch_the_file_when_content_is_unchanged()
    {
        Run(GoodList);
        var inode = Inode(Target);
        var mtime = File.GetLastWriteTimeUtc(Target);
        Thread.Sleep(1100);
        var r = Run(GoodList);
        Assert.Equal(0, r.Exit);
        Assert.Contains("no change", r.Output);
        Assert.Equal(inode, Inode(Target));
        Assert.Equal(mtime, File.GetLastWriteTimeUtc(Target));
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void Replaces_the_file_atomically_when_content_changes()
    {
        Run(GoodList);
        var inode = Inode(Target);
        var updated = "ssh-ed25519 " + Fixtures.Ed25519Blob + " only_one\n";
        Assert.Equal(0, Run(updated).Exit);
        Assert.Equal(updated, File.ReadAllText(Target));
        Assert.NotEqual(inode, Inode(Target)); // new inode == rename, not an in-place rewrite
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void A_successful_empty_response_clears_the_managed_file()
    {
        Run(GoodList);
        var r = Run("");
        Assert.Equal(0, r.Exit);
        Assert.True(File.Exists(Target));
        Assert.Equal("", File.ReadAllText(Target));
    }

    [Fact]
    public void A_successful_empty_response_creates_an_empty_file_on_first_run()
    {
        Assert.Equal(0, Run("").Exit);
        Assert.Equal("", File.ReadAllText(Target));
    }

    [Theory]
    [InlineData("500")]
    [InlineData("404")]
    [InlineData("403")]
    [InlineData("302")]
    [InlineData("304")]
    [InlineData("204")]
    public void Non_200_responses_keep_the_existing_file(string code)
    {
        Run(GoodList);
        var r = Run("ssh-ed25519 " + Fixtures.Ed25519Blob + " replacement\n", code);
        Assert.NotEqual(0, r.Exit);
        Assert.Equal(GoodList, File.ReadAllText(Target));
        Assert.Empty(TempFiles());
    }

    [Theory]
    [InlineData(28)] // timeout
    [InlineData(6)]  // DNS failure
    [InlineData(60)] // TLS verification failure
    [InlineData(63)] // max-filesize exceeded
    public void Network_and_tls_errors_keep_the_existing_file_even_with_a_partial_body(int curlExit)
    {
        Run(GoodList);
        var r = Run("ssh-ed25519 " + Fixtures.Ed25519Blob + " partial\n", "200", curlExit);
        Assert.NotEqual(0, r.Exit);
        Assert.Equal(GoodList, File.ReadAllText(Target));
        Assert.Empty(TempFiles());
    }

    public static TheoryData<string, string> BadPayloads => new()
    {
        { "html", "<html><body>Captive portal</body></html>\n" },
        { "html-without-newline", "<html>login</html>" },
        { "options-prefix", "command=\"/bin/evil\" ssh-ed25519 " + Fixtures.Ed25519Blob + " x\n" },
        { "no-trailing-newline", "ssh-ed25519 " + Fixtures.Ed25519Blob + " x" },
        { "blank-line", "ssh-ed25519 " + Fixtures.Ed25519Blob + " x\n\n" },
        { "crlf", "ssh-ed25519 " + Fixtures.Ed25519Blob + " x\r\n" },
        { "comment-with-space", "ssh-ed25519 " + Fixtures.Ed25519Blob + " two words\n" },
        { "one-bad-line-among-good", GoodList + "garbage line\n" },
        { "unknown-algorithm", "ssh-dss " + Fixtures.Ed25519Blob + " x\n" },
        { "cert-algorithm", "ssh-ed25519-cert-v01@openssh.com " + Fixtures.Ed25519Blob + " x\n" },
        { "private-key", Fixtures.PrivateKey },
    };

    [Theory]
    [MemberData(nameof(BadPayloads))]
    public void Malformed_payloads_keep_the_existing_file(string name, string payload)
    {
        _ = name;
        Run(GoodList);
        var r = Run(payload);
        Assert.NotEqual(0, r.Exit);
        Assert.Equal(GoodList, File.ReadAllText(Target));
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void A_payload_containing_a_nul_byte_is_rejected()
    {
        Run(GoodList);
        var bytes = System.Text.Encoding.ASCII.GetBytes("ssh-ed25519 " + Fixtures.Ed25519Blob + " ok\n").Concat(new byte[] { 0 })
            .Concat(System.Text.Encoding.ASCII.GetBytes("\n")).ToArray();
        Assert.NotEqual(0, Run(null, rawBody: bytes).Exit);
        Assert.Equal(GoodList, File.ReadAllText(Target));
    }

    [Fact]
    public void Refuses_a_plain_http_url_without_calling_curl()
    {
        var r = Run(GoodList, url: "http://keys.example.test/api/authorized-keys");
        Assert.NotEqual(0, r.Exit);
        Assert.False(File.Exists(CurlLog));
        Assert.False(File.Exists(Target));
    }

    [Fact]
    public void Curl_is_invoked_with_strict_tls_and_timeouts()
    {
        Run(GoodList);
        var args = File.ReadAllText(CurlLog);
        Assert.DoesNotContain(" -k", " " + args);
        Assert.DoesNotContain("--insecure", args);
        Assert.Contains("--proto =https", args);
        Assert.Contains("--max-time", args);
        Assert.Contains("--connect-timeout", args);
        Assert.Contains("--max-filesize", args);
        Assert.DoesNotContain("--location", args); // no redirects, in particular none to plain http
    }

    [Fact]
    public async Task Server_output_for_awkward_labels_is_accepted_by_the_client()
    {
        using var db = new TestDb();
        var keys = new KeyService(db, TimeProvider.System);
        await keys.AddAsync("Wälker's Laptop 🙂 \"quoted\"", Fixtures.Ed25519, "t");
        await keys.AddAsync("  spaces  in   label ", Fixtures.Rsa3072, "t");
        await keys.AddAsync("日本語", Fixtures.Ecdsa256, "t");
        await keys.AddAsync("sk", Fixtures.SkEd25519(), "t");
        var body = (await new AuthorizedKeysService(db).GetAsync()).Body;

        var r = Run(body);
        Assert.Equal(0, r.Exit);
        Assert.Equal(body, File.ReadAllText(Target));
        Assert.Equal(4, body.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [Fact]
    public async Task Server_empty_list_clears_the_client_file()
    {
        using var db = new TestDb();
        Run(GoodList);
        var body = (await new AuthorizedKeysService(db).GetAsync()).Body;
        Assert.Equal(0, Run(body).Exit);
        Assert.Equal("", File.ReadAllText(Target));
    }

    [Fact]
    public void Shell_scripts_have_valid_syntax()
    {
        foreach (var f in new[] { "ssh-buddy-sync", "install.sh" })
        {
            using var p = Process.Start(new ProcessStartInfo("bash", ["-n", Path.Combine(RepoRoot(), "client", f)]) { RedirectStandardError = true })!;
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, p.StandardError.ReadToEnd());
        }
    }

    private static long Inode(string path)
    {
        using var p = Process.Start(new ProcessStartInfo("stat", ["-c", "%i", path]) { RedirectStandardOutput = true })!;
        var s = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return long.Parse(s.Trim());
    }
}

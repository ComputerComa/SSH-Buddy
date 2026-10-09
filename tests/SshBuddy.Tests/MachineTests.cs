using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SshBuddy.Tests.Support;
using SshBuddy.Web.Data;
using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

public class FqdnNormalizerTests
{
    [Theory]
    [InlineData("web1.example.com", "web1.example.com")]
    [InlineData("WEB1.Example.COM", "web1.example.com")]
    [InlineData("web1.example.com.", "web1.example.com")]
    [InlineData("  web1.example.com  ", "web1.example.com")]
    [InlineData("a-b.c-d.lan", "a-b.c-d.lan")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    [InlineData("1web.home.arpa", "1web.home.arpa")]
    public void Normalizes_to_one_canonical_form(string input, string expected)
    {
        Assert.Null(FqdnNormalizer.TryNormalize(input, out var fqdn));
        Assert.Equal(expected, fqdn);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("web1")]                       // not fully qualified
    [InlineData("web1.")]
    [InlineData("web 1.example.com")]
    [InlineData("web1.example.com..")]         // only one trailing dot is forgiven
    [InlineData("-web.example.com")]
    [InlineData("web-.example.com")]
    [InlineData("we_b.example.com")]
    [InlineData("web1.example.123")]           // all-numeric TLD: looks like an IP
    [InlineData("10.0.0.5")]
    [InlineData("a..b.example")]
    [InlineData("web1.exam\nple.com")]
    [InlineData("web\u0000.example.com")]
    public void Rejects_invalid_names(string? input) =>
        Assert.NotNull(FqdnNormalizer.TryNormalize(input, out _));

    [Fact]
    public void Rejects_over_long_labels_and_names()
    {
        Assert.NotNull(FqdnNormalizer.TryNormalize(new string('a', 64) + ".example.com", out _));
        Assert.NotNull(FqdnNormalizer.TryNormalize(string.Join('.', Enumerable.Repeat(new string('a', 60), 5)), out _));
    }
}

public sealed class RecordingSink : IMachineEventSink
{
    public List<MachineEvent> Registered { get; } = [];
    public List<MachineEvent> IpChanged { get; } = [];
    public bool Throw { get; set; }

    public Task MachineRegisteredAsync(MachineEvent e, CancellationToken ct)
    {
        Registered.Add(e);
        return Throw ? throw new InvalidOperationException("sink down") : Task.CompletedTask;
    }

    public Task MachineIpChangedAsync(MachineEvent e, CancellationToken ct)
    {
        IpChanged.Add(e);
        return Throw ? throw new InvalidOperationException("sink down") : Task.CompletedTask;
    }
}

public sealed class MachineServiceTests : IDisposable
{
    private readonly TestDb _db = new();
    private readonly FakeTime _time = new();
    private readonly RecordingSink _sink = new();
    private readonly MachineService _machines;
    private readonly TemplateCredentialService _templates;
    private readonly string _template;

    public MachineServiceTests() : this(new MachineOptions()) { }

    private MachineServiceTests(MachineOptions options)
    {
        _machines = new MachineService(_db, _time, Options.Create(options), _sink, NullLogger<MachineService>.Instance);
        _templates = new TemplateCredentialService(_db, _time);
        _template = _templates.CreateAsync("debian-13", "admin").GetAwaiter().GetResult().Created!.Token;
    }

    public void Dispose() => _db.Dispose();

    private static string Nonce() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private Task<EnrollMachineResult> Enroll(string host, string nonce, string? template = null, string ip = "10.0.0.5") =>
        _machines.EnrollAsync(template ?? _template, host, nonce, "1.0.0", ip);

    private Task<CheckInResult> Report(string credential, string result = "success", string? error = null, string? etag = "\"abc\"", string ip = "10.0.0.5") =>
        _machines.CheckInAsync(credential, new CheckInReport("1.0.0", result, error, etag), ip);

    private async Task<Machine> Row(string fqdn)
    {
        await using var db = _db.CreateDbContext();
        return await db.Machines.AsNoTracking().SingleAsync(m => m.Fqdn == fqdn);
    }

    private async Task<MachineView> View(string fqdn) => (await _machines.ListAsync()).Single(v => v.Machine.Fqdn == fqdn);

    // ------------------------------------------------------------ enrollment permissions

    [Fact]
    public async Task Template_credential_enrolls_machines_and_stores_only_hashes()
    {
        var nonce = Nonce();
        var r = await Enroll("web1.example.com", nonce);
        Assert.Equal(EnrollMachineStatus.Issued, r.Status);
        Assert.StartsWith("sbm_", r.MachineCredential);

        var row = await Row("web1.example.com");
        Assert.NotEqual(r.MachineCredential, row.CredentialHash);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(r.MachineCredential!))), row.CredentialHash);
        Assert.DoesNotContain(nonce, row.EnrollmentNonceHash);
        Assert.Equal(_time.GetUtcNow().UtcDateTime, row.FirstRegisteredUtc);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("sbt_wrong")]
    public async Task Unknown_template_credentials_cannot_enroll(string? token)
    {
        var r = await _machines.EnrollAsync(token, "web1.example.com", Nonce(), "1.0.0", "1.1.1.1");
        Assert.Equal(EnrollMachineStatus.InvalidCredential, r.Status);
        Assert.Empty(await _machines.ListAsync());
    }

    [Fact]
    public async Task Revoked_template_credential_cannot_enroll_but_existing_machines_keep_working()
    {
        var first = await Enroll("web1.example.com", Nonce());
        var id = (await _templates.ListAsync()).Single().Id;
        Assert.True(await _templates.RevokeAsync(id, "admin"));

        Assert.Equal(EnrollMachineStatus.InvalidCredential, (await Enroll("web2.example.com", Nonce())).Status);
        Assert.Equal(CheckInStatus.Ok, (await Report(first.MachineCredential!)).Status);
    }

    [Fact]
    public async Task Credentials_of_the_other_kinds_cannot_be_used_across_endpoints()
    {
        var keyUploadToken = (await new EnrollmentService(_db, _time, Options.Create(new EnrollmentOptions())).CreateTokenAsync("admin")).Token;
        Assert.Equal(EnrollMachineStatus.InvalidCredential, (await _machines.EnrollAsync(keyUploadToken, "web1.example.com", Nonce(), "1", null)).Status);

        var machine = await Enroll("web1.example.com", Nonce());
        // a machine credential cannot enroll further machines, nor check in as another kind
        Assert.Equal(EnrollMachineStatus.InvalidCredential, (await _machines.EnrollAsync(machine.MachineCredential, "web2.example.com", Nonce(), "1", null)).Status);
        // a template credential cannot report
        Assert.Equal(CheckInStatus.Unauthorized, (await Report(_template)).Status);
        // and neither can authenticate the single-use *key upload* flow
        var keys = new EnrollmentService(_db, _time, Options.Create(new EnrollmentOptions()));
        Assert.Equal(EnrollStatus.InvalidToken, (await keys.EnrollAsync(_template, "x", Fixtures.Ed25519)).Status);
        Assert.Equal(EnrollStatus.InvalidToken, (await keys.EnrollAsync(machine.MachineCredential, "x", Fixtures.Ed25519)).Status);
        await using var db = _db.CreateDbContext();
        Assert.Equal(0, await db.Keys.CountAsync());
    }

    [Fact]
    public async Task Machine_enrollment_does_not_consume_key_upload_tokens()
    {
        var keys = new EnrollmentService(_db, _time, Options.Create(new EnrollmentOptions()));
        var token = await keys.CreateTokenAsync("admin");
        await Enroll("web1.example.com", Nonce());
        Assert.Equal(EnrollStatus.Enrolled, (await keys.EnrollAsync(token.Token, "laptop", Fixtures.Ed25519)).Status);
    }

    [Theory]
    [InlineData("web1", "A fully qualified")]
    [InlineData("web 1.example.com", "whitespace")]
    public async Task Invalid_hostnames_are_rejected_without_creating_machines(string host, string message)
    {
        var r = await Enroll(host, Nonce());
        Assert.Equal(EnrollMachineStatus.InvalidInput, r.Status);
        Assert.Contains(message, r.Error);
        Assert.Empty(await _machines.ListAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("has spaces in it which is not a valid nonce")]
    public async Task A_valid_nonce_is_required(string? nonce)
    {
        var r = await _machines.EnrollAsync(_template, "web1.example.com", nonce, "1", null);
        Assert.Equal(EnrollMachineStatus.InvalidInput, r.Status);
    }

    // ------------------------------------------------------------ collisions and never overwriting

    [Theory]
    [InlineData("WEB1.example.com")]
    [InlineData("web1.example.com.")]
    [InlineData(" Web1.Example.Com ")]
    public async Task Same_hostname_in_any_spelling_collides_and_never_replaces_the_credential(string spelling)
    {
        var original = await Enroll("web1.example.com", Nonce());
        await Report(original.MachineCredential!); // confirmed

        var intruder = await Enroll(spelling, Nonce(), ip: "10.9.9.9");
        Assert.Equal(EnrollMachineStatus.Conflict, intruder.Status);
        Assert.Null(intruder.MachineCredential);

        Assert.Single(await _machines.ListAsync());
        Assert.Equal(CheckInStatus.Ok, (await Report(original.MachineCredential!)).Status); // original still valid
        var view = await View("web1.example.com");
        Assert.True(view.ReenrollRequested);
        Assert.Equal("10.9.9.9", view.Machine.LastRefusedEnrollIp);
    }

    [Fact]
    public async Task A_pending_machine_is_protected_from_a_different_requester()
    {
        var a = await Enroll("web1.example.com", Nonce());
        var b = await Enroll("web1.example.com", Nonce()); // a clone with the same template credential, different nonce
        Assert.Equal(EnrollMachineStatus.Conflict, b.Status);
        Assert.Equal(CheckInStatus.Ok, (await Report(a.MachineCredential!)).Status);
    }

    [Fact]
    public async Task Parallel_enrollments_of_one_hostname_with_different_nonces_yield_exactly_one_success()
    {
        const int N = 16;
        using var barrier = new Barrier(N);
        var results = await Task.WhenAll(Enumerable.Range(0, N).Select(_ => Task.Run(async () =>
        {
            var svc = new MachineService(_db, _time, Options.Create(new MachineOptions()), new NullMachineEventSink(), NullLogger<MachineService>.Instance);
            barrier.SignalAndWait();
            return await svc.EnrollAsync(_template, "race.example.com", Nonce(), "1", "10.0.0.1");
        })));
        Assert.Equal(1, results.Count(r => r.Status == EnrollMachineStatus.Issued));
        Assert.Equal(N - 1, results.Count(r => r.Status == EnrollMachineStatus.Conflict));
        Assert.Single(await _machines.ListAsync());
        var winner = results.Single(r => r.Status == EnrollMachineStatus.Issued);
        Assert.Equal(CheckInStatus.Ok, (await Report(winner.MachineCredential!)).Status);
    }

    // ------------------------------------------------------------ interrupted enrollment

    [Fact]
    public async Task Lost_response_is_recovered_by_retrying_with_the_same_nonce()
    {
        var nonce = Nonce();
        var lost = await Enroll("web1.example.com", nonce);          // response never reaches the machine
        var retry = await Enroll("web1.example.com", nonce);         // agent still holds its nonce
        Assert.Equal(EnrollMachineStatus.Issued, retry.Status);
        Assert.NotEqual(lost.MachineCredential, retry.MachineCredential);

        Assert.Equal(CheckInStatus.Unauthorized, (await Report(lost.MachineCredential!)).Status); // superseded
        Assert.Equal(CheckInStatus.Ok, (await Report(retry.MachineCredential!)).Status);
        Assert.Single(await _machines.ListAsync());
    }

    [Fact]
    public async Task Once_confirmed_the_same_nonce_no_longer_re_issues()
    {
        var nonce = Nonce();
        var first = await Enroll("web1.example.com", nonce);
        await Report(first.MachineCredential!);                      // first authenticated check-in confirms it
        var again = await Enroll("web1.example.com", nonce);
        Assert.Equal(EnrollMachineStatus.Conflict, again.Status);
        Assert.Equal(CheckInStatus.Ok, (await Report(first.MachineCredential!)).Status);
        Assert.Null((await Row("web1.example.com")).EnrollmentNonceHash);
    }

    [Fact]
    public async Task Concurrent_retries_with_one_nonce_leave_exactly_one_working_credential()
    {
        var nonce = Nonce();
        await Enroll("web1.example.com", nonce);
        const int N = 8;
        using var barrier = new Barrier(N);
        var results = await Task.WhenAll(Enumerable.Range(0, N).Select(_ => Task.Run(async () =>
        {
            var svc = new MachineService(_db, _time, Options.Create(new MachineOptions()), new NullMachineEventSink(), NullLogger<MachineService>.Instance);
            barrier.SignalAndWait();
            return await svc.EnrollAsync(_template, "web1.example.com", nonce, "1", null);
        })));
        var issued = results.Where(r => r.Status == EnrollMachineStatus.Issued).ToList();
        Assert.NotEmpty(issued);
        var working = 0;
        foreach (var r in issued) if ((await Report(r.MachineCredential!)).Status == CheckInStatus.Ok) working++;
        Assert.Equal(1, working);
    }

    // ------------------------------------------------------------ revocation and permits

    [Fact]
    public async Task Removing_a_machine_disables_its_credential_and_blocks_silent_re_enrollment()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!);
        var id = (await Row("web1.example.com")).Id;

        Assert.True(await _machines.RevokeAsync(id, "admin"));
        Assert.Equal(CheckInStatus.Unauthorized, (await Report(m.MachineCredential!)).Status);
        Assert.Equal(MachineStatus.Revoked, (await View("web1.example.com")).Status);
        Assert.Null((await Row("web1.example.com")).CredentialHash);

        // the old installation retries with the shared template credential (and even its old nonce): refused
        var retry = await Enroll("web1.example.com", Nonce());
        Assert.Equal(EnrollMachineStatus.Conflict, retry.Status);
        Assert.Contains("removed", retry.Error);
        Assert.True((await View("web1.example.com")).ReenrollRequested);
    }

    [Fact]
    public async Task Permit_lets_a_rebuilt_machine_enroll_exactly_once()
    {
        var old = await Enroll("web1.example.com", Nonce());
        await Report(old.MachineCredential!);
        var id = (await Row("web1.example.com")).Id;
        await Enroll("web1.example.com", Nonce());                    // rebuilt machine is refused...
        Assert.True((await View("web1.example.com")).ReenrollRequested);

        Assert.True(await _machines.PermitReenrollAsync(id, "admin"));
        Assert.True((await View("web1.example.com")).PermitActive);

        var nonce = Nonce();
        var rebuilt = await Enroll("web1.example.com", nonce, ip: "10.0.0.77");
        Assert.Equal(EnrollMachineStatus.Issued, rebuilt.Status);
        Assert.Equal(CheckInStatus.Unauthorized, (await Report(old.MachineCredential!)).Status);   // old credential replaced
        Assert.Equal(CheckInStatus.Ok, (await Report(rebuilt.MachineCredential!, ip: "10.0.0.77")).Status);

        var view = await View("web1.example.com");
        Assert.False(view.PermitActive);
        Assert.False(view.ReenrollRequested);

        // the permit was single use: the old container cannot grab it afterwards
        Assert.Equal(EnrollMachineStatus.Conflict, (await Enroll("web1.example.com", Nonce())).Status);
    }

    [Fact]
    public async Task Permit_also_revives_a_removed_machine_and_keeps_its_history()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!);
        var before = await Row("web1.example.com");
        await _machines.RevokeAsync(before.Id, "admin");
        await _machines.PermitReenrollAsync(before.Id, "admin");

        Assert.Equal(EnrollMachineStatus.Issued, (await Enroll("web1.example.com", Nonce())).Status);
        var after = await Row("web1.example.com");
        Assert.Null(after.RevokedUtc);
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(before.FirstRegisteredUtc, after.FirstRegisteredUtc);
    }

    [Fact]
    public async Task Permit_expires()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!);
        await _machines.PermitReenrollAsync((await Row("web1.example.com")).Id, "admin");
        _time.Advance(TimeSpan.FromMinutes(241));
        Assert.Equal(EnrollMachineStatus.Conflict, (await Enroll("web1.example.com", Nonce())).Status);
        Assert.False((await View("web1.example.com")).PermitActive);
    }

    [Fact]
    public async Task Removing_clears_a_pending_permit()
    {
        var m = await Enroll("web1.example.com", Nonce());
        var id = (await Row("web1.example.com")).Id;
        await _machines.PermitReenrollAsync(id, "admin");
        await _machines.RevokeAsync(id, "admin");
        Assert.Equal(EnrollMachineStatus.Conflict, (await Enroll("web1.example.com", Nonce())).Status);
        _ = m;
    }

    [Fact]
    public async Task Admin_actions_on_unknown_machines_report_not_found()
    {
        Assert.False(await _machines.RevokeAsync(Guid.NewGuid(), "admin"));
        Assert.False(await _machines.PermitReenrollAsync(Guid.NewGuid(), "admin"));
    }

    // ------------------------------------------------------------ check-in

    [Fact]
    public async Task Check_in_is_idempotent_and_uses_server_time_and_address()
    {
        var m = await Enroll("web1.example.com", Nonce(), ip: "10.0.0.5");
        _time.Advance(TimeSpan.FromMinutes(5));
        var t1 = _time.GetUtcNow().UtcDateTime;
        await Report(m.MachineCredential!, ip: "10.0.0.6");
        var one = await Row("web1.example.com");
        await Report(m.MachineCredential!, ip: "10.0.0.6");
        var two = await Row("web1.example.com");

        Assert.Equal(t1, one.LastContactUtc);
        Assert.Equal("10.0.0.6", one.LastIp);
        Assert.Equal(one.LastResult, two.LastResult);
        Assert.Equal(one.AppliedEtag, two.AppliedEtag);
        Assert.Equal(one.ConfirmedUtc, two.ConfirmedUtc);
        Assert.Single(await _machines.ListAsync());
        Assert.Equal(one.CredentialHash, two.CredentialHash);
    }

    [Fact]
    public async Task Check_in_records_errors_without_marking_the_machine_healthy()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!, "error", "server answered HTTP 500\u0007\n with junk");
        var v = await View("web1.example.com");
        Assert.Equal(MachineStatus.SyncError, v.Status);
        Assert.Null(v.Machine.LastSuccessUtc);
        Assert.DoesNotContain('\n', v.Machine.LastError!);
        Assert.Contains("HTTP 500", v.Machine.LastError);
    }

    [Fact]
    public async Task A_long_error_is_truncated()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!, "error", new string('x', 5000));
        Assert.Equal(500, (await Row("web1.example.com")).LastError!.Length);
    }

    [Theory]
    [InlineData("done")]
    [InlineData("")]
    [InlineData(null)]
    public async Task Check_in_validates_the_result_value(string? result)
    {
        var m = await Enroll("web1.example.com", Nonce());
        var r = await _machines.CheckInAsync(m.MachineCredential, new CheckInReport("1.0.0", result, null, null), "1.1.1.1");
        Assert.Equal(CheckInStatus.InvalidInput, r.Status);
    }

    [Fact]
    public async Task A_successful_report_after_an_error_clears_the_error_and_keeps_history()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!, "success");
        var good = (await Row("web1.example.com")).LastSuccessUtc;
        _time.Advance(TimeSpan.FromMinutes(5));
        await Report(m.MachineCredential!, "error", "boom");
        var failed = await Row("web1.example.com");
        Assert.Equal(good, failed.LastSuccessUtc);   // the failure did not erase the last success
        _time.Advance(TimeSpan.FromMinutes(5));
        await Report(m.MachineCredential!, "success");
        var recovered = await Row("web1.example.com");
        Assert.Null(recovered.LastError);
        Assert.True(recovered.LastSuccessUtc > good);
    }

    // ------------------------------------------------------------ status

    [Fact]
    public async Task Status_is_healthy_only_after_a_successful_sync_report()
    {
        var m = await Enroll("web1.example.com", Nonce());
        Assert.Equal(MachineStatus.SyncError, (await View("web1.example.com")).Status);   // enrolled, nothing reported
        await Report(m.MachineCredential!, "error", "no network to key list");
        Assert.Equal(MachineStatus.SyncError, (await View("web1.example.com")).Status);   // checking in but cannot sync
        await Report(m.MachineCredential!, "success");
        Assert.Equal(MachineStatus.Healthy, (await View("web1.example.com")).Status);
    }

    [Fact]
    public async Task Machine_becomes_stale_after_the_threshold_and_leaves_stale_on_an_authenticated_check_in()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!);
        _time.Advance(TimeSpan.FromDays(2.9));
        Assert.Equal(MachineStatus.Healthy, (await View("web1.example.com")).Status);
        _time.Advance(TimeSpan.FromDays(0.2));
        Assert.Equal(MachineStatus.Stale, (await View("web1.example.com")).Status);

        // not deleted, not revoked: its credential still works and it returns to healthy by itself
        Assert.Equal(CheckInStatus.Ok, (await Report(m.MachineCredential!)).Status);
        Assert.Equal(MachineStatus.Healthy, (await View("web1.example.com")).Status);
    }

    [Fact]
    public async Task A_returning_stale_machine_that_cannot_sync_becomes_sync_error_not_healthy()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!);
        _time.Advance(TimeSpan.FromDays(10));
        await Report(m.MachineCredential!, "error", "TLS verification failed");
        Assert.Equal(MachineStatus.SyncError, (await View("web1.example.com")).Status);
    }

    [Fact]
    public async Task Stale_threshold_is_configurable()
    {
        var svc = new MachineService(_db, _time, Options.Create(new MachineOptions { StaleAfterDays = 0.5 }), _sink, NullLogger<MachineService>.Instance);
        var m = await svc.EnrollAsync(_template, "web1.example.com", Nonce(), "1", null);
        await svc.CheckInAsync(m.MachineCredential, new CheckInReport("1.0.0", "success", null, null), null);
        _time.Advance(TimeSpan.FromHours(13));
        Assert.Equal(MachineStatus.Stale, (await svc.ListAsync()).Single().Status);
    }

    [Fact]
    public async Task Stale_machines_are_never_deleted_or_revoked_automatically()
    {
        var m = await Enroll("web1.example.com", Nonce());
        await Report(m.MachineCredential!);
        _time.Advance(TimeSpan.FromDays(400));
        var all = await _machines.ListAsync();
        Assert.Single(all);
        Assert.Equal(MachineStatus.Stale, all[0].Status);
        Assert.NotNull((await Row("web1.example.com")).CredentialHash);
    }

    // ------------------------------------------------------------ audit, events, secrets

    [Fact]
    public async Task Audit_trail_records_registration_distinctly_and_never_contains_secrets()
    {
        var nonce = Nonce();
        var m = await Enroll("web1.example.com", nonce);
        await Enroll("web1.example.com", nonce);                       // re-issue
        await Report(m.MachineCredential!);
        var id = (await Row("web1.example.com")).Id;
        await _machines.PermitReenrollAsync(id, "admin");
        await _machines.RevokeAsync(id, "admin");

        await using var db = _db.CreateDbContext();
        var events = await db.AuditEvents.OrderBy(a => a.Id).ToListAsync();
        var actions = events.Select(a => a.Action).ToList();
        Assert.Contains(MachineAuditActions.MachineRegistered, actions);
        Assert.Contains(MachineAuditActions.MachineCredentialReissued, actions);
        Assert.Contains(MachineAuditActions.MachineReenrollPermitted, actions);
        Assert.Contains(MachineAuditActions.MachineRevoked, actions);
        Assert.Contains(MachineAuditActions.TemplateCredentialCreated, actions);

        var everything = string.Join('\n', events.Select(a => a.Detail + a.Actor));
        var rows = await db.Machines.AsNoTracking().ToListAsync();
        foreach (var secret in new[] { _template, m.MachineCredential!, nonce })
            Assert.DoesNotContain(secret, everything);
        Assert.DoesNotContain(Secrets_Hash(_template), everything);
        Assert.NotEmpty(rows);
    }

    private static string Secrets_Hash(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    [Fact]
    public async Task Template_credential_is_stored_hashed_and_shown_only_by_the_create_call()
    {
        await using var db = _db.CreateDbContext();
        var row = await db.TemplateCredentials.SingleAsync();
        Assert.Equal(Secrets_Hash(_template), row.TokenHash);
        Assert.NotEqual(_template, row.TokenHash);
        var (created, error) = await _templates.CreateAsync("   ", "admin");
        Assert.Null(created);
        Assert.NotNull(error);
    }

    [Fact]
    public async Task Registration_and_ip_changes_raise_events_for_later_integrations_and_sink_failures_are_harmless()
    {
        var m = await Enroll("web1.example.com", Nonce(), ip: "10.0.0.5");
        Assert.Equal("web1.example.com", _sink.Registered.Single().Fqdn);

        await Report(m.MachineCredential!, ip: "10.0.0.5");
        Assert.Empty(_sink.IpChanged);
        _sink.Throw = true;
        Assert.Equal(CheckInStatus.Ok, (await Report(m.MachineCredential!, ip: "10.0.0.9")).Status);
        var change = _sink.IpChanged.Single();
        Assert.Equal(("10.0.0.5", "10.0.0.9"), (change.PreviousIp, change.Ip));

        var other = await Enroll("web2.example.com", Nonce());     // sink throws on registration too
        Assert.Equal(EnrollMachineStatus.Issued, other.Status);
    }
}

public sealed class AgentReleaseServiceTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshbuddy-rel-").FullName;
    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private AgentReleaseService Svc(string? pinned = null) =>
        new(Options.Create(new AgentOptions { ReleaseDirectory = _dir, Version = pinned }));

    private void Release(string version, bool amd64 = true, bool arm64 = true, bool corruptSums = false, bool omitSums = false)
    {
        var d = Directory.CreateDirectory(Path.Combine(_dir, version)).FullName;
        var lines = new List<string>();
        foreach (var (platform, present) in new[] { ("linux-amd64", amd64), ("linux-arm64", arm64) })
        {
            if (!present) continue;
            var name = $"ssh-buddy-agent-{platform}";
            var bytes = Encoding.UTF8.GetBytes($"binary {version} {platform}");
            File.WriteAllBytes(Path.Combine(d, name), bytes);
            lines.Add($"{(corruptSums ? new string('0', 64) : Secrets_Hash(bytes))}  {name}");
        }
        if (!omitSums) File.WriteAllLines(Path.Combine(d, "SHA256SUMS"), lines);
    }

    private static string Secrets_Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));

    [Fact]
    public void No_releases_means_no_manifest() => Assert.Null(Svc().GetManifest());

    [Fact]
    public void Complete_release_lists_version_platform_size_and_checksum()
    {
        Release("1.2.3");
        var m = Svc().GetManifest()!;
        Assert.Equal("1.2.3", m.Version);
        var amd = m.Binaries.Single(b => b.Platform == "linux-amd64");
        var bytes = Encoding.UTF8.GetBytes("binary 1.2.3 linux-amd64");
        Assert.Equal(bytes.Length, amd.Size);
        Assert.Equal(Secrets_Hash(bytes), amd.Sha256);
        Assert.Equal("/api/agent/download/1.2.3/linux-amd64", amd.Path);
        Assert.Contains($"1.2.3 linux-amd64 {bytes.Length} {amd.Sha256} /api/agent/download/1.2.3/linux-amd64\n", m.ToText());
        Assert.Equal(2, m.ToText().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [Theory]
    [InlineData(false, true, false, false)]   // missing amd64
    [InlineData(true, false, false, false)]   // missing arm64
    [InlineData(true, true, true, false)]     // SHA256SUMS disagrees with the files
    [InlineData(true, true, false, true)]     // no SHA256SUMS
    public void Incomplete_or_inconsistent_releases_are_not_served(bool amd, bool arm, bool corrupt, bool omit)
    {
        Release("1.0.0", amd, arm, corrupt, omit);
        Assert.Null(Svc().GetManifest());
        Assert.Null(Svc().Find("1.0.0", "linux-amd64"));
    }

    [Fact]
    public void Highest_complete_version_wins_prereleases_rank_below_and_incomplete_ones_are_skipped()
    {
        Release("1.2.0"); Release("1.10.0-rc1"); Release("2.0.0", arm64: false);
        Assert.Equal("1.10.0-rc1", Svc().GetManifest()!.Version);   // numeric compare: 1.10 > 1.2; 2.0.0 is incomplete
        Release("1.10.0");
        Assert.Equal("1.10.0", Svc().GetManifest()!.Version);        // a release outranks its prerelease
    }

    [Fact]
    public void A_pinned_version_is_served_even_if_a_newer_one_exists()
    {
        Release("1.0.0"); Release("2.0.0");
        Assert.Equal("1.0.0", Svc("1.0.0").GetManifest()!.Version);
        Assert.Null(Svc("9.9.9").GetManifest());
    }

    [Theory]
    [InlineData("..", "linux-amd64")]
    [InlineData("../1.0.0", "linux-amd64")]
    [InlineData("1.0.0", "../SHA256SUMS")]
    [InlineData("1.0.0", "linux-386")]
    [InlineData("1.0.0", "SHA256SUMS")]
    [InlineData("1.0", "linux-amd64")]
    [InlineData("1.0.0/../1.0.0", "linux-amd64")]
    public void Download_lookups_cannot_escape_the_release_directory(string version, string platform)
    {
        Release("1.0.0");
        Assert.Null(Svc().Find(version, platform));
    }

    [Fact]
    public void A_changed_binary_is_rehashed_and_stops_matching_until_the_build_rewrites_the_sums()
    {
        Release("1.0.0");
        var svc = Svc();
        Assert.NotNull(svc.GetManifest());
        File.WriteAllText(Path.Combine(_dir, "1.0.0", "ssh-buddy-agent-linux-amd64"), "tampered, and a different length");
        Assert.Null(svc.GetManifest());
    }
}

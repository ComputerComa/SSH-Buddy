using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SshBuddy.Tests.Support;
using SshBuddy.Web.Data;
using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

public sealed class KeyServiceTests : IDisposable
{
    private readonly TestDb _db = new();
    private readonly FakeTime _time = new();
    private readonly KeyService _keys;

    public KeyServiceTests() => _keys = new KeyService(_db, _time);
    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task Adds_a_key_with_audit_entry()
    {
        var r = await _keys.AddAsync("laptop", Fixtures.Ed25519, "admin");
        Assert.True(r.Succeeded);
        Assert.Equal(Fixtures.Ed25519Fingerprint, r.Key!.Fingerprint);
        await using var db = _db.CreateDbContext();
        var audit = await db.AuditEvents.SingleAsync();
        Assert.Equal(AuditActions.KeyAdded, audit.Action);
        Assert.Equal("admin", audit.Actor);
    }

    [Fact]
    public async Task Rejects_duplicate_key_material_regardless_of_comment_and_label()
    {
        await _keys.AddAsync("laptop", Fixtures.Ed25519, "admin");
        var r = await _keys.AddAsync("other name", "ssh-ed25519 " + Fixtures.Ed25519Blob + " a different comment", "admin");
        Assert.Equal(AddKeyStatus.Duplicate, r.Status);
        Assert.Single(await _keys.ListAsync());
    }

    [Fact]
    public async Task Invalid_input_is_rejected_and_not_stored()
    {
        Assert.Equal(AddKeyStatus.Invalid, (await _keys.AddAsync("x", Fixtures.PrivateKey, "a")).Status);
        Assert.Equal(AddKeyStatus.Invalid, (await _keys.AddAsync("", Fixtures.Ed25519, "a")).Status);
        Assert.Empty(await _keys.ListAsync());
    }

    [Fact]
    public async Task Revoke_and_reactivate_are_audited_and_reflected_in_the_distribution_list()
    {
        var id = (await _keys.AddAsync("laptop", Fixtures.Ed25519, "admin")).Key!.Id;
        var dist = new AuthorizedKeysService(_db);

        Assert.True(await _keys.SetRevokedAsync(id, true, "admin"));
        Assert.Equal("", (await dist.GetAsync()).Body);
        Assert.False((await _keys.ListAsync()).Single().IsActive);

        Assert.True(await _keys.SetRevokedAsync(id, false, "admin"));
        Assert.Contains(Fixtures.Ed25519Blob, (await dist.GetAsync()).Body);

        await using var db = _db.CreateDbContext();
        Assert.Equal(
            [AuditActions.KeyAdded, AuditActions.KeyRevoked, AuditActions.KeyReactivated],
            await db.AuditEvents.OrderBy(a => a.Id).Select(a => a.Action).ToListAsync());
        Assert.False(await _keys.SetRevokedAsync(Guid.NewGuid(), true, "admin"));
    }

    [Fact]
    public async Task Revoking_twice_does_not_write_a_second_audit_entry()
    {
        var id = (await _keys.AddAsync("laptop", Fixtures.Ed25519, "admin")).Key!.Id;
        await _keys.SetRevokedAsync(id, true, "admin");
        await _keys.SetRevokedAsync(id, true, "admin");
        await using var db = _db.CreateDbContext();
        Assert.Equal(1, await db.AuditEvents.CountAsync(a => a.Action == AuditActions.KeyRevoked));
    }
}

public sealed class AuthorizedKeysServiceTests : IDisposable
{
    private readonly TestDb _db = new();
    private readonly FakeTime _time = new();
    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task Empty_list_is_a_valid_empty_document_with_a_stable_etag()
    {
        var svc = new AuthorizedKeysService(_db);
        var a = await svc.GetAsync();
        Assert.Equal("", a.Body);
        Assert.Equal(a.ETag, (await svc.GetAsync()).ETag);
        Assert.StartsWith("\"", a.ETag);
    }

    [Fact]
    public async Task Output_is_ordered_independently_of_insertion_order_and_etag_tracks_content()
    {
        var keys = new KeyService(_db, _time);
        var svc = new AuthorizedKeysService(_db);
        string[] lines = [Fixtures.Ed25519, Fixtures.Ed25519Other, Fixtures.Rsa3072, Fixtures.Ecdsa256];
        foreach (var l in lines) await keys.AddAsync("k", l, "a");
        var first = await svc.GetAsync();

        using var db2 = new TestDb();
        var keys2 = new KeyService(db2, _time);
        foreach (var l in lines.Reverse()) await keys2.AddAsync("k", l, "a");
        var second = await new AuthorizedKeysService(db2).GetAsync();

        Assert.Equal(first.Body, second.Body);
        Assert.Equal(first.ETag, second.ETag);
        Assert.Equal(4, first.Body.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
        Assert.EndsWith("\n", first.Body);

        await keys.AddAsync("new", Fixtures.RandomEd25519(), "a");
        Assert.NotEqual(first.ETag, (await svc.GetAsync()).ETag);
    }

    [Fact]
    public async Task Never_emits_the_user_supplied_comment_or_options()
    {
        var keys = new KeyService(_db, _time);
        await keys.AddAsync("evil\" command=\"x", "ssh-ed25519 " + Fixtures.Ed25519Blob + " command=\"/bin/sh\"", "a");
        var body = (await new AuthorizedKeysService(_db).GetAsync()).Body.TrimEnd('\n');
        Assert.DoesNotContain(" ", body.Split(' ', 3)[2]);
        Assert.StartsWith("ssh-ed25519 ", body);
        Assert.DoesNotContain("/bin/sh", body);
    }
}

public sealed class EnrollmentServiceTests : IDisposable
{
    private readonly TestDb _db = new();
    private readonly FakeTime _time = new();
    private readonly EnrollmentService _svc;

    public EnrollmentServiceTests() =>
        _svc = new EnrollmentService(_db, _time, Options.Create(new EnrollmentOptions { TokenLifetimeMinutes = 15 }));
    public void Dispose() => _db.Dispose();

    private async Task<int> KeyCount() { await using var db = _db.CreateDbContext(); return await db.Keys.CountAsync(); }

    [Fact]
    public async Task Valid_token_enrolls_once_and_only_once()
    {
        var t = await _svc.CreateTokenAsync("admin");
        var first = await _svc.EnrollAsync(t.Token, "host1", Fixtures.Ed25519);
        Assert.Equal(EnrollStatus.Enrolled, first.Status);
        var second = await _svc.EnrollAsync(t.Token, "host2", Fixtures.Ed25519Other);
        Assert.Equal(EnrollStatus.InvalidToken, second.Status);
        Assert.Equal(1, await KeyCount());
    }

    [Fact]
    public async Task Only_a_hash_is_stored_and_secrets_never_reach_the_audit_trail()
    {
        var t = await _svc.CreateTokenAsync("admin");
        await _svc.EnrollAsync(t.Token, "host1", Fixtures.Ed25519);
        await using var db = _db.CreateDbContext();
        var row = await db.EnrollmentTokens.SingleAsync();
        Assert.NotEqual(t.Token, row.TokenHash);
        Assert.DoesNotContain(t.Token, row.TokenHash);
        Assert.NotNull(row.ConsumedUtc);
        foreach (var a in await db.AuditEvents.ToListAsync())
        {
            Assert.DoesNotContain(t.Token, a.Detail);
            Assert.DoesNotContain(row.TokenHash, a.Detail);
        }
        Assert.Contains(db.AuditEvents, a => a.Action == AuditActions.EnrollmentTokenCreated);
        Assert.Contains(db.AuditEvents, a => a.Action == AuditActions.EnrollmentTokenUsed);
    }

    [Fact]
    public async Task Token_expires()
    {
        var t = await _svc.CreateTokenAsync("admin");
        Assert.Equal(_time.GetUtcNow().UtcDateTime.AddMinutes(15), t.ExpiresUtc);
        _time.Advance(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(1));
        Assert.Equal(EnrollStatus.InvalidToken, (await _svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519)).Status);
        Assert.Equal(0, await KeyCount());
    }

    [Fact]
    public async Task Token_is_still_valid_just_before_expiry()
    {
        var t = await _svc.CreateTokenAsync("admin");
        _time.Advance(TimeSpan.FromMinutes(14));
        Assert.Equal(EnrollStatus.Enrolled, (await _svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519)).Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("sbe_notarealtoken")]
    public async Task Unknown_tokens_are_rejected(string? token)
    {
        Assert.Equal(EnrollStatus.InvalidToken, (await _svc.EnrollAsync(token, "h", Fixtures.Ed25519)).Status);
        Assert.Equal(0, await KeyCount());
    }

    [Fact]
    public async Task Invalid_input_does_not_consume_the_token()
    {
        var t = await _svc.CreateTokenAsync("admin");
        Assert.Equal(EnrollStatus.InvalidInput, (await _svc.EnrollAsync(t.Token, "h", Fixtures.PrivateKey)).Status);
        Assert.Equal(EnrollStatus.InvalidInput, (await _svc.EnrollAsync(t.Token, "", Fixtures.Ed25519)).Status);
        Assert.Equal(EnrollStatus.InvalidInput, (await _svc.EnrollAsync(t.Token, "h", "command=\"x\" " + Fixtures.Ed25519)).Status);
        Assert.Equal(EnrollStatus.Enrolled, (await _svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519)).Status);
    }

    [Fact]
    public async Task Duplicate_key_does_not_consume_the_token()
    {
        await new KeyService(_db, _time).AddAsync("existing", Fixtures.Ed25519, "admin");
        var t = await _svc.CreateTokenAsync("admin");
        Assert.Equal(EnrollStatus.Duplicate, (await _svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519)).Status);
        Assert.Equal(EnrollStatus.Enrolled, (await _svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519Other)).Status);
    }

    [Fact]
    public async Task Failed_insert_rolls_the_token_consumption_back()
    {
        // Simulate losing the duplicate race after the pre-check: a unique index violation inside the transaction.
        var t = await _svc.CreateTokenAsync("admin");
        var parsed = PublicKeyParser.Parse(Fixtures.Ed25519).Key!;
        var racing = new RacingFactory(_db, parsed);
        var svc = new EnrollmentService(racing, _time, Options.Create(new EnrollmentOptions()));
        Assert.Equal(EnrollStatus.Duplicate, (await svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519)).Status);
        // Token must still be usable for a different key.
        Assert.Equal(EnrollStatus.Enrolled, (await _svc.EnrollAsync(t.Token, "h", Fixtures.Ed25519Other)).Status);
    }

    /// <summary>
    /// Inserts the same key through another connection right before the enrollment transaction begins,
    /// i.e. after the duplicate pre-check passed but before this transaction holds the write lock.
    /// </summary>
    private sealed class RacingFactory(TestDb inner, ParsedPublicKey key) : IDbContextFactory<AppDbContext>
    {
        private readonly RivalInsert _interceptor = new(inner, key);

        public AppDbContext CreateDbContext() =>
            new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(inner.ConnectionString).AddInterceptors(_interceptor).Options);
    }

    private sealed class RivalInsert(TestDb db, ParsedPublicKey key) : Microsoft.EntityFrameworkCore.Diagnostics.DbTransactionInterceptor
    {
        private int _fired;

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbTransaction>> TransactionStartingAsync(
            System.Data.Common.DbConnection connection,
            Microsoft.EntityFrameworkCore.Diagnostics.TransactionStartingEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbTransaction> result,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref _fired, 1) == 0)
            {
                using var rival = db.CreateDbContext();
                rival.Keys.Add(new SshKey { Label = "rival", Algorithm = key.Algorithm, KeyMaterial = key.KeyMaterial, Fingerprint = key.Fingerprint });
                rival.SaveChanges();
            }
            return base.TransactionStartingAsync(connection, eventData, result, cancellationToken);
        }
    }

    [Fact]
    public async Task Concurrent_requests_with_one_token_yield_exactly_one_key()
    {
        const int N = 24;
        var t = await _svc.CreateTokenAsync("admin");
        using var barrier = new Barrier(N);
        var tasks = Enumerable.Range(0, N).Select(i => Task.Run(async () =>
        {
            // Each task has its own service instance, DbContext and SQLite connection.
            var svc = new EnrollmentService(_db, _time, Options.Create(new EnrollmentOptions()));
            barrier.SignalAndWait();
            return await svc.EnrollAsync(t.Token, $"host{i}", Fixtures.RandomEd25519($"h{i}"));
        })).ToArray();

        var results = await Task.WhenAll(tasks); // any "database is locked" exception would fail here
        Assert.Equal(1, results.Count(r => r.Status == EnrollStatus.Enrolled));
        Assert.Equal(N - 1, results.Count(r => r.Status == EnrollStatus.InvalidToken));
        Assert.Equal(1, await KeyCount());
        await using var db = _db.CreateDbContext();
        Assert.Equal(1, await db.AuditEvents.CountAsync(a => a.Action == AuditActions.EnrollmentTokenUsed));
    }
}

public sealed class StoredKeyDefenceTests : IDisposable
{
    private readonly TestDb _db = new();
    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task A_stored_key_that_fails_todays_validation_is_never_served_but_good_keys_still_are()
    {
        var good = new KeyService(_db, new FakeTime());
        await good.AddAsync("good", Fixtures.Ed25519, "t");

        // as if added before a validation fix, or inserted by hand: an off-curve ECDSA point
        var junk = new byte[64];
        Random.Shared.NextBytes(junk);
        var blob = Fixtures.Blob(Fixtures.Ascii("ecdsa-sha2-nistp256"), Fixtures.Ascii("nistp256"), new byte[] { 4 }.Concat(junk).ToArray());
        await using (var db = _db.CreateDbContext())
        {
            db.Keys.Add(new SshBuddy.Web.Data.SshKey
            {
                Label = "legacy-bad", Algorithm = "ecdsa-sha2-nistp256", KeyMaterial = Convert.ToBase64String(blob),
                Fingerprint = "SHA256:x", CreatedUtc = DateTime.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        var body = (await new AuthorizedKeysService(_db).GetAsync()).Body;
        Assert.Contains(Fixtures.Ed25519Blob, body);
        Assert.DoesNotContain("legacy-bad", body);
        Assert.Single(body.Split('\n', StringSplitOptions.RemoveEmptyEntries));
    }
}

public sealed class UpgradeFromSliceOneTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshbuddy-upgrade-").FullName;
    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    [Fact]
    public async Task An_existing_slice_one_database_upgrades_without_losing_keys_audit_or_the_distributed_list()
    {
        var cs = $"Data Source={Path.Combine(_dir, "old.db")}";
        var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<SshBuddy.Web.Data.AppDbContext>().UseSqlite(cs).Options;

        // 1. the database exactly as slice one left it (only the Initial migration applied), with data in it
        await using (var old = new SshBuddy.Web.Data.AppDbContext(options))
        {
            var migrator = Microsoft.EntityFrameworkCore.Infrastructure.AccessorExtensions.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>(old);
            migrator.Migrate("20261009170204_Initial");
            Assert.DoesNotContain(old.Database.GetAppliedMigrations(), m => m.EndsWith("AddMachines"));
            await old.Database.ExecuteSqlRawAsync("""
                INSERT INTO "Keys" ("Id","Label","Algorithm","KeyMaterial","Fingerprint","CreatedUtc","RevokedUtc") VALUES
                  ('11111111-1111-1111-1111-111111111111','alice','ssh-ed25519','AAAAC3NzaC1lZDI1NTE5AAAAIMgXTvJTR9gazAPocNC4rL8cutrwxP4HUcSYPQAmkdoc','SHA256:gZDwIlFyJUsv3SZrSLW/QYwi2MQFMTwKTlrBqPloFkw','2026-01-01 00:00:00',NULL),
                  ('22222222-2222-2222-2222-222222222222','old laptop','ssh-ed25519','AAAAC3NzaC1lZDI1NTE5AAAAIES06xsqQXHq7oscHhCzOk6qP/zPtkO/quGMqUoEXuFI','SHA256:RuNC4i6ezlmCi0tx745Syzra+YFPJARmr2A8o+8yWoE','2026-01-02 00:00:00','2026-02-01 00:00:00');
                INSERT INTO "AuditEvents" ("TimestampUtc","Action","Actor","Detail") VALUES ('2026-01-01 00:00:00','KeyAdded','admin','alice');
                """);
        }
        var factory = new FixedFactory(options);
        var before = await new AuthorizedKeysService(factory).GetAsync();

        // 2. the upgrade the operator runs: `SshBuddy.Web migrate`
        await using (var db = new SshBuddy.Web.Data.AppDbContext(options))
        {
            await db.Database.MigrateAsync();
            Assert.Contains(await db.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("AddMachines"));
            Assert.Equal(2, await db.Keys.CountAsync());
            Assert.Equal(1, await db.AuditEvents.CountAsync());
            Assert.Equal(0, await db.Machines.CountAsync());
            Assert.Equal(0, await db.TemplateCredentials.CountAsync());
        }

        // 3. what machines download is byte-for-byte what they got before the upgrade (same ETag, so no spurious change)
        var after = await new AuthorizedKeysService(factory).GetAsync();
        Assert.Equal(before.Body, after.Body);
        Assert.Equal(before.ETag, after.ETag);
        Assert.Contains("alice", after.Body);
        Assert.DoesNotContain("old_laptop", after.Body);   // the revoked key stays revoked
    }

    private sealed class FixedFactory(Microsoft.EntityFrameworkCore.DbContextOptions<SshBuddy.Web.Data.AppDbContext> o)
        : Microsoft.EntityFrameworkCore.IDbContextFactory<SshBuddy.Web.Data.AppDbContext>
    {
        public SshBuddy.Web.Data.AppDbContext CreateDbContext() => new(o);
    }
}

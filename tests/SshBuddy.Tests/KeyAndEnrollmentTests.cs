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

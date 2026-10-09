using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SshBuddy.Web.Data;

namespace SshBuddy.Tests.Support;

/// <summary>A migrated, file-backed SQLite database (an in-memory one cannot show real lock behaviour).</summary>
public sealed class TestDb : IDbContextFactory<AppDbContext>, IDisposable
{
    public string Dir { get; } = Directory.CreateTempSubdirectory("sshbuddy-test-").FullName;
    public string ConnectionString => $"Data Source={Path.Combine(Dir, "test.db")}";
    private readonly DbContextOptions<AppDbContext> _options;

    public TestDb()
    {
        _options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(ConnectionString).Options;
        using var db = CreateDbContext();
        db.Database.Migrate();
        db.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
    }

    public AppDbContext CreateDbContext() => new(_options);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(Dir, recursive: true); } catch (IOException) { }
    }
}

public sealed class FakeTime(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;
    public FakeTime() : this(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero)) { }
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}

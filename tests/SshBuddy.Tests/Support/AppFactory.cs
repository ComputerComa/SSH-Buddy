using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SshBuddy.Web.Data;

namespace SshBuddy.Tests.Support;

public sealed class AppFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@example.test";
    public const string AdminPassword = "correct horse battery staple";

    private readonly string _dir = Directory.CreateTempSubdirectory("sshbuddy-web-").FullName;
    private readonly Dictionary<string, string> _settings;

    private readonly string? _environment;
    private readonly Action<IServiceCollection>? _configureServices;

    public AppFactory(Dictionary<string, string>? settings = null, string? environment = null, Action<IServiceCollection>? configureServices = null)
    {
        _settings = settings ?? [];
        _environment = environment;
        _configureServices = configureServices;
    }

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        // UseSetting is applied before Program reads configuration (ConfigureAppConfiguration is too late).
        builder.UseSetting("ConnectionStrings:Default", $"Data Source={Path.Combine(_dir, "web.db")}");
        builder.UseSetting("DataProtection:KeysDirectory", Path.Combine(_dir, "keys"));
        foreach (var (k, v) in _settings) builder.UseSetting(k, v);
        if (_environment is not null) builder.UseEnvironment(_environment);
        if (_configureServices is not null) builder.ConfigureTestServices(_configureServices);
    }

    /// <summary>Migrates and creates the admin. Call once after construction.</summary>
    public async Task<AppFactory> InitializeAsync()
    {
        await using var scope = Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.MigrateAsync();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var r = await users.CreateAsync(new IdentityUser { UserName = AdminEmail, Email = AdminEmail }, AdminPassword);
        Assert.True(r.Succeeded);
        return this;
    }

    public HttpClient CreateNoRedirectClient(Uri? baseAddress = null) =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false,
            BaseAddress = baseAddress ?? new Uri("http://localhost"),
        });

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}

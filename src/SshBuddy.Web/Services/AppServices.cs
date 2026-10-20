using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public static class AppServices
{
    /// <summary>
    /// <c>Security:RequireHttps</c> (default: on outside Development). Off is for operators who run SSH Buddy over plain
    /// HTTP on purpose: the API then answers http, the UI is not redirected and the login cookie is not marked Secure.
    /// </summary>
    public static bool RequireHttps(IConfiguration config, IHostEnvironment env) =>
        config.GetValue("Security:RequireHttps", !env.IsDevelopment());

    public static IServiceCollection AddSshBuddyCore(this IServiceCollection services, IConfiguration config, IWebHostEnvironment env)
    {
        var connectionString = config.GetConnectionString("Default") ?? "Data Source=App_Data/sshbuddy.db";
        EnsureDirectoryFor(connectionString);

        void Configure(DbContextOptionsBuilder o) => o.UseSqlite(connectionString);
        services.AddDbContextFactory<AppDbContext>(Configure);
        services.AddDbContext<AppDbContext>(Configure, optionsLifetime: ServiceLifetime.Singleton);

        services.AddIdentityCore<IdentityUser>(o =>
            {
                o.User.RequireUniqueEmail = true;
                o.Password.RequiredLength = 12;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequireDigit = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                o.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddSignInManager();

        services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();
        services.ConfigureApplicationCookie(o =>
        {
            o.LoginPath = "/login";
            o.AccessDeniedPath = "/login";
            o.Cookie.Name = "SshBuddy.Auth";
            o.Cookie.HttpOnly = true;
            o.Cookie.SameSite = SameSiteMode.Lax;
            o.Cookie.SecurePolicy = RequireHttps(config, env) ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            o.ExpireTimeSpan = TimeSpan.FromHours(8);
            o.SlidingExpiration = true;
        });

        var keysDir = config["DataProtection:KeysDirectory"] ?? "App_Data/keys";
        Directory.CreateDirectory(keysDir);
        services.AddDataProtection().SetApplicationName("SshBuddy").PersistKeysToFileSystem(new DirectoryInfo(keysDir));

        services.AddSingleton(TimeProvider.System);
        services.Configure<EnrollmentOptions>(config.GetSection("Enrollment"));
        services.AddScoped<KeyService>();
        services.AddScoped<EnrollmentService>();
        services.AddScoped<AuthorizedKeysService>();

        services.Configure<MachineOptions>(config.GetSection("Machines"));
        services.Configure<AgentOptions>(config.GetSection("Agent"));
        services.AddSingleton<IMachineEventSink, NullMachineEventSink>();
        services.AddScoped<TemplateCredentialService>();
        services.AddScoped<MachineService>();
        services.AddSingleton<AgentReleaseService>();
        return services;
    }

    private static void EnsureDirectoryFor(string connectionString)
    {
        var dir = Path.GetDirectoryName(new SqliteConnectionStringBuilder(connectionString).DataSource);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }
}

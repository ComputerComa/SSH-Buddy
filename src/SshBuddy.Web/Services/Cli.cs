using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

/// <summary>Operator commands: <c>migrate</c>, <c>admin create</c>, <c>admin reset-password</c>.</summary>
public static class Cli
{
    public static bool IsCommand(string[] args) => args.Length > 0 && args[0] is "migrate" or "admin";

    public static async Task<int> RunAsync(string[] args)
    {
        var builder = WebApplication.CreateBuilder([]);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddSshBuddyCore(builder.Configuration, builder.Environment);
        await using var app = builder.Build();
        await using var scope = app.Services.CreateAsyncScope();

        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.MigrateAsync();
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");

        switch (args)
        {
            case ["migrate"]:
                Console.WriteLine("Database is up to date.");
                return 0;
            case ["admin", "create", ..]:
                return await CreateAdminAsync(scope.ServiceProvider, args[2..]);
            case ["admin", "reset-password", ..]:
                return await ResetPasswordAsync(scope.ServiceProvider, args[2..]);
            default:
                Console.Error.WriteLine("""
                    Usage:
                      migrate
                      admin create --email <email> [--password-stdin]
                      admin reset-password --email <email> [--password-stdin]
                    """);
                return 2;
        }
    }

    private static async Task<int> CreateAdminAsync(IServiceProvider sp, string[] opts)
    {
        var users = sp.GetRequiredService<UserManager<IdentityUser>>();
        if (await users.Users.AnyAsync())
        {
            Console.Error.WriteLine("An administrator already exists. Use 'admin reset-password' to change the password.");
            return 1;
        }
        if (!TryGetInput(opts, out var email, out var password)) return 2;

        var user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
        var result = await users.CreateAsync(user, password);
        if (!result.Succeeded) return Report(result);
        Console.WriteLine($"Administrator '{email}' created.");
        return 0;
    }

    private static async Task<int> ResetPasswordAsync(IServiceProvider sp, string[] opts)
    {
        var users = sp.GetRequiredService<UserManager<IdentityUser>>();
        if (!TryGetInput(opts, out var email, out var password)) return 2;
        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            Console.Error.WriteLine("No such administrator.");
            return 1;
        }
        var token = await users.GeneratePasswordResetTokenAsync(user);
        var result = await users.ResetPasswordAsync(user, token, password);
        if (!result.Succeeded) return Report(result);
        await users.ResetAccessFailedCountAsync(user);
        await users.SetLockoutEndDateAsync(user, null);
        Console.WriteLine("Password updated.");
        return 0;
    }

    private static int Report(IdentityResult result)
    {
        foreach (var e in result.Errors) Console.Error.WriteLine($"Error: {e.Description}");
        return 1;
    }

    private static bool TryGetInput(string[] opts, out string email, out string password)
    {
        email = password = "";
        var i = Array.IndexOf(opts, "--email");
        if (i < 0 || i + 1 >= opts.Length)
        {
            Console.Error.WriteLine("--email <email> is required.");
            return false;
        }
        email = opts[i + 1];

        if (opts.Contains("--password-stdin"))
        {
            password = Console.In.ReadLine() ?? "";
        }
        else if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine("Input is redirected; pass --password-stdin to read the password from stdin.");
            return false;
        }
        else
        {
            password = ReadHidden("Password: ");
            if (ReadHidden("Confirm password: ") != password)
            {
                Console.Error.WriteLine("Passwords do not match.");
                return false;
            }
        }
        return true;
    }

    private static string ReadHidden(string prompt)
    {
        Console.Error.Write(prompt);
        var sb = new System.Text.StringBuilder();
        while (Console.ReadKey(intercept: true) is var k && k.Key != ConsoleKey.Enter)
        {
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
            else if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
        }
        Console.Error.WriteLine();
        return sb.ToString();
    }
}

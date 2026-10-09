using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public sealed record CreatedTemplateCredential(Guid Id, string Name, string Token);

public class TemplateCredentialService(IDbContextFactory<AppDbContext> dbFactory, TimeProvider time)
{
    public const string Prefix = "sbt_";

    public async Task<(CreatedTemplateCredential? Created, string? Error)> CreateAsync(string? name, string actor, CancellationToken ct = default)
    {
        name = name?.Trim() ?? "";
        if (name.Length is 0 or > 64 || name.Any(char.IsControl))
            return (null, "Give the credential a name of 1–64 characters (for example the template it is baked into).");

        var token = Prefix + Secrets.NewToken();
        var now = time.GetUtcNow().UtcDateTime;
        var entity = new TemplateCredential { Name = name, TokenHash = Secrets.Hash(token), CreatedUtc = now };

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        db.TemplateCredentials.Add(entity);
        db.AuditEvents.Add(new AuditEvent
        {
            TimestampUtc = now,
            Action = MachineAuditActions.TemplateCredentialCreated,
            Actor = actor,
            Detail = $"{name} ({entity.Id})",
        });
        await db.SaveChangesAsync(ct);
        return (new CreatedTemplateCredential(entity.Id, name, token), null);
    }

    public async Task<List<TemplateCredential>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.TemplateCredentials.AsNoTracking().OrderBy(t => t.CreatedUtc).ToListAsync(ct);
    }

    /// <summary>Stops new enrollments with this credential. Machines already enrolled keep their own credentials.</summary>
    public async Task<bool> RevokeAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var row = await db.TemplateCredentials.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (row is null) return false;
        if (row.RevokedUtc is not null) return true;
        row.RevokedUtc = now;
        db.AuditEvents.Add(new AuditEvent
        {
            TimestampUtc = now,
            Action = MachineAuditActions.TemplateCredentialRevoked,
            Actor = actor,
            Detail = $"{row.Name} ({row.Id})",
        });
        await db.SaveChangesAsync(ct);
        return true;
    }
}

internal static class Secrets
{
    public static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Hash(string secret) =>
        Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret)));
}

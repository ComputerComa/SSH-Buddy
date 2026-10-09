using Microsoft.EntityFrameworkCore;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public enum AddKeyStatus { Added, Invalid, Duplicate }

public sealed record AddKeyResult(AddKeyStatus Status, string? Error = null, SshKey? Key = null)
{
    public bool Succeeded => Status == AddKeyStatus.Added;
}

public class KeyService(IDbContextFactory<AppDbContext> dbFactory, TimeProvider time)
{
    public async Task<List<SshKey>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Keys.AsNoTracking()
            .OrderBy(k => k.Label).ThenBy(k => k.KeyMaterial)
            .ToListAsync(ct);
    }

    public async Task<AddKeyResult> AddAsync(string? label, string? publicKey, string actor, CancellationToken ct = default)
    {
        var validated = Validate(label, publicKey, out var parsed, out var normalizedLabel);
        if (validated is not null) return validated;

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        if (await db.Keys.AnyAsync(k => k.KeyMaterial == parsed!.KeyMaterial, ct))
            return Duplicate();

        var key = Build(parsed!, normalizedLabel, time.GetUtcNow().UtcDateTime);
        db.Keys.Add(key);
        db.AuditEvents.Add(Audit(AuditActions.KeyAdded, actor, key, time));
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation())
        {
            return Duplicate();
        }
        return new AddKeyResult(AddKeyStatus.Added, Key: key);
    }

    /// <returns>false when the key does not exist.</returns>
    public async Task<bool> SetRevokedAsync(Guid id, bool revoked, string actor, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var key = await db.Keys.FirstOrDefaultAsync(k => k.Id == id, ct);
        if (key is null) return false;
        if (key.IsActive == !revoked) return true; // already in the requested state

        key.RevokedUtc = revoked ? time.GetUtcNow().UtcDateTime : null;
        db.AuditEvents.Add(Audit(revoked ? AuditActions.KeyRevoked : AuditActions.KeyReactivated, actor, key, time));
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Shared validation for UI and enrollment. Returns a failure result, or null when valid.</summary>
    internal static AddKeyResult? Validate(string? label, string? publicKey, out ParsedPublicKey? parsed, out string normalizedLabel)
    {
        parsed = null;
        var labelError = KeyLabel.Validate(label, out normalizedLabel);
        if (labelError is not null) return new AddKeyResult(AddKeyStatus.Invalid, labelError);

        var result = PublicKeyParser.Parse(publicKey);
        if (!result.IsValid) return new AddKeyResult(AddKeyStatus.Invalid, result.Error);

        parsed = result.Key;
        return null;
    }

    internal static AddKeyResult Duplicate() =>
        new(AddKeyStatus.Duplicate, "This public key is already registered.");

    internal static SshKey Build(ParsedPublicKey parsed, string label, DateTime nowUtc) => new()
    {
        Label = label,
        Algorithm = parsed.Algorithm,
        KeyMaterial = parsed.KeyMaterial,
        Fingerprint = parsed.Fingerprint,
        CreatedUtc = nowUtc,
    };

    internal static AuditEvent Audit(string action, string actor, SshKey key, TimeProvider time) => new()
    {
        TimestampUtc = time.GetUtcNow().UtcDateTime,
        Action = action,
        Actor = actor,
        Detail = $"{key.Label} ({key.Algorithm} {key.Fingerprint})",
    };
}

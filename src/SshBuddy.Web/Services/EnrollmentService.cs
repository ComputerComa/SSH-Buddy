using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public class EnrollmentOptions
{
    public int TokenLifetimeMinutes { get; set; } = 15;
}

public sealed record CreatedToken(string Token, DateTime ExpiresUtc);

public enum EnrollStatus { Enrolled, InvalidToken, InvalidInput, Duplicate }

public sealed record EnrollResult(EnrollStatus Status, string? Error = null, SshKey? Key = null);

public class EnrollmentService(
    IDbContextFactory<AppDbContext> dbFactory,
    TimeProvider time,
    IOptions<EnrollmentOptions> options)
{
    private const string TokenPrefix = "sbe_";
    private const int MaxTokenLength = 128;

    public async Task<CreatedToken> CreateTokenAsync(string actor, CancellationToken ct = default)
    {
        var token = TokenPrefix + Base64Url(RandomNumberGenerator.GetBytes(32));
        var now = time.GetUtcNow().UtcDateTime;
        var entity = new EnrollmentToken
        {
            TokenHash = Hash(token),
            CreatedUtc = now,
            ExpiresUtc = now.AddMinutes(options.Value.TokenLifetimeMinutes),
        };

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        db.EnrollmentTokens.Add(entity);
        db.AuditEvents.Add(new AuditEvent
        {
            TimestampUtc = now,
            Action = AuditActions.EnrollmentTokenCreated,
            Actor = actor,
            Detail = $"token {entity.Id} expires {entity.ExpiresUtc:u}",
        });
        await db.SaveChangesAsync(ct);
        return new CreatedToken(token, entity.ExpiresUtc);
    }

    /// <summary>
    /// Validates input first (so bad input never burns the token), then consumes the token and
    /// inserts the key in one transaction. The token is consumed by a conditional UPDATE, so of
    /// any number of concurrent requests exactly one can match it.
    /// </summary>
    public async Task<EnrollResult> EnrollAsync(string? token, string? label, string? publicKey, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
            return new EnrollResult(EnrollStatus.InvalidToken);
        var hash = Hash(token);

        await using var db = await dbFactory.CreateDbContextAsync(ct);

        var now = time.GetUtcNow().UtcDateTime;
        if (!await db.EnrollmentTokens.AnyAsync(t => t.TokenHash == hash && t.ConsumedUtc == null && t.ExpiresUtc > now, ct))
            return new EnrollResult(EnrollStatus.InvalidToken);

        var invalid = KeyService.Validate(label, publicKey, out var parsed, out var normalizedLabel);
        if (invalid is not null) return new EnrollResult(EnrollStatus.InvalidInput, invalid.Error);

        if (await db.Keys.AnyAsync(k => k.KeyMaterial == parsed!.KeyMaterial, ct))
            return new EnrollResult(EnrollStatus.Duplicate, KeyService.Duplicate().Error);

        var key = KeyService.Build(parsed!, normalizedLabel, now);

        // The first statement in the transaction is the write, so SQLite takes the write lock
        // up front and concurrent requests queue behind it instead of failing on lock upgrade.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        now = time.GetUtcNow().UtcDateTime;
        var consumed = await db.EnrollmentTokens
            .Where(t => t.TokenHash == hash && t.ConsumedUtc == null && t.ExpiresUtc > now)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.ConsumedUtc, now)
                .SetProperty(t => t.ConsumedKeyId, key.Id), ct);
        if (consumed != 1)
            return new EnrollResult(EnrollStatus.InvalidToken);

        db.Keys.Add(key);
        db.AuditEvents.Add(KeyService.Audit(AuditActions.KeyEnrolled, "enrollment", key, time));
        db.AuditEvents.Add(new AuditEvent
        {
            TimestampUtc = now,
            Action = AuditActions.EnrollmentTokenUsed,
            Actor = "enrollment",
            Detail = $"key {key.Id}",
        });
        try
        {
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation())
        {
            // Lost a race with another insert of the same key: the rollback un-consumes the token.
            return new EnrollResult(EnrollStatus.Duplicate, KeyService.Duplicate().Error);
        }
        return new EnrollResult(EnrollStatus.Enrolled, Key: key);
    }

    private static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public sealed record AuthorizedKeysDocument(string Body, string ETag);

public class AuthorizedKeysService(IDbContextFactory<AppDbContext> dbFactory, ILogger<AuthorizedKeysService>? log = null)
{
    public async Task<AuthorizedKeysDocument> GetAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var keys = await db.Keys.AsNoTracking()
            .Where(k => k.RevokedUtc == null)
            .OrderBy(k => k.KeyMaterial) // SQLite BINARY collation: ordinal, so stable across requests
            .Select(k => new { k.Algorithm, k.KeyMaterial, k.Label })
            .ToListAsync(ct);

        var sb = new StringBuilder();
        foreach (var k in keys)
        {
            // Defence in depth: the agent rejects the WHOLE list if one line is invalid, so a stored key that does
            // not pass today's validation (added before a validation fix, or inserted by hand) must never be served.
            if (!PublicKeyParser.Parse($"{k.Algorithm} {k.KeyMaterial}").IsValid)
            {
                log?.LogWarning("Skipping stored key '{Label}' from the distributed list: it fails validation.", k.Label);
                continue;
            }
            sb.Append(k.Algorithm).Append(' ').Append(k.KeyMaterial).Append(' ')
              .Append(KeyLabel.ToComment(k.Label)).Append('\n');
        }

        var body = sb.ToString();
        var etag = "\"" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)))[..32] + "\"";
        return new AuthorizedKeysDocument(body, etag);
    }
}

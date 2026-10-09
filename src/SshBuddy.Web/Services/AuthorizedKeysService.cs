using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public sealed record AuthorizedKeysDocument(string Body, string ETag);

public class AuthorizedKeysService(IDbContextFactory<AppDbContext> dbFactory)
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
            sb.Append(k.Algorithm).Append(' ').Append(k.KeyMaterial).Append(' ')
              .Append(KeyLabel.ToComment(k.Label)).Append('\n');

        var body = sb.ToString();
        var etag = "\"" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body)))[..32] + "\"";
        return new AuthorizedKeysDocument(body, etag);
    }
}

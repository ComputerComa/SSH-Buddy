using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace SshBuddy.Web.Services;

internal static class DbExceptionExtensions
{
    private const int SqliteConstraint = 19;

    public static bool IsUniqueViolation(this DbUpdateException ex) =>
        ex.InnerException is SqliteException { SqliteErrorCode: SqliteConstraint } s
        && s.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase);
}

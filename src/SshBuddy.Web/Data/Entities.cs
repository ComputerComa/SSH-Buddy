namespace SshBuddy.Web.Data;

public class SshKey
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Label { get; set; }
    public required string Algorithm { get; set; }

    /// <summary>Base64 key blob. Unique: the algorithm is encoded inside the blob.</summary>
    public required string KeyMaterial { get; set; }

    public required string Fingerprint { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }

    public bool IsActive => RevokedUtc is null;
}

public class EnrollmentToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Hex SHA-256 of the token. The token itself is never stored.</summary>
    public required string TokenHash { get; set; }

    public DateTime CreatedUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public DateTime? ConsumedUtc { get; set; }
    public Guid? ConsumedKeyId { get; set; }
}

public class AuditEvent
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public required string Action { get; set; }
    public required string Actor { get; set; }
    public required string Detail { get; set; }
}

public static class AuditActions
{
    public const string KeyAdded = "KeyAdded";
    public const string KeyEnrolled = "KeyEnrolled";
    public const string KeyRevoked = "KeyRevoked";
    public const string KeyReactivated = "KeyReactivated";
    public const string EnrollmentTokenCreated = "EnrollmentTokenCreated";
    public const string EnrollmentTokenUsed = "EnrollmentTokenUsed";
}

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

/// <summary>
/// Reusable credential baked into an LXC template. Authorizes machine enrollment ONLY:
/// it cannot manage keys, upload keys or read the UI. Only its hash is stored.
/// </summary>
public class TemplateCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string TokenHash { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime? LastUsedUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
}

/// <summary>
/// A machine, identified by its normalized FQDN. A revoked machine keeps its row as a tombstone so that an
/// old installation cannot silently re-enroll with the shared template credential.
/// </summary>
public class Machine
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Fqdn { get; set; }

    /// <summary>Hash of the per-machine reporting credential; null once revoked.</summary>
    public string? CredentialHash { get; set; }

    /// <summary>
    /// Hash of the nonce the agent generated when it enrolled. While the machine is unconfirmed, only a retry
    /// carrying the same nonce may be re-issued the credential (lost-response recovery).
    /// </summary>
    public string? EnrollmentNonceHash { get; set; }

    public Guid? TemplateCredentialId { get; set; }
    public DateTime FirstRegisteredUtc { get; set; }
    public DateTime? CredentialIssuedUtc { get; set; }

    /// <summary>Set by the first authenticated check-in; after that the credential can only be replaced by an admin permit.</summary>
    public DateTime? ConfirmedUtc { get; set; }

    public DateTime LastContactUtc { get; set; }
    public DateTime? LastSuccessUtc { get; set; }
    public string? LastIp { get; set; }
    public string? AgentVersion { get; set; }
    public string? AppliedEtag { get; set; }

    /// <summary>"success" or "error" as reported by the agent; null before the first report.</summary>
    public string? LastResult { get; set; }
    public string? LastError { get; set; }

    public DateTime? RevokedUtc { get; set; }

    /// <summary>Single-use, time-limited admin permission for a rebuilt machine to enroll under this hostname.</summary>
    public DateTime? ReenrollPermittedUntilUtc { get; set; }

    public DateTime? LastRefusedEnrollUtc { get; set; }
    public string? LastRefusedEnrollIp { get; set; }
}

public static class MachineAuditActions
{
    public const string TemplateCredentialCreated = "TemplateCredentialCreated";
    public const string TemplateCredentialRevoked = "TemplateCredentialRevoked";
    public const string MachineRegistered = "MachineRegistered";
    public const string MachineCredentialReissued = "MachineCredentialReissued";
    public const string MachineReenrolled = "MachineReenrolled";
    public const string MachineReenrollPermitted = "MachineReenrollPermitted";
    public const string MachineRevoked = "MachineRevoked";
}

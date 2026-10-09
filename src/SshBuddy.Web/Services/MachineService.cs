using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public partial class MachineService(
    IDbContextFactory<AppDbContext> dbFactory,
    TimeProvider time,
    IOptions<MachineOptions> options,
    IMachineEventSink events,
    ILogger<MachineService> log)
{
    public const string CredentialPrefix = "sbm_";
    private const int MaxSecretLength = 128;

    [GeneratedRegex("^[A-Za-z0-9_-]{22,128}$")]
    private static partial Regex NonceRegex();

    [GeneratedRegex("^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")]
    private static partial Regex VersionRegex();

    private TimeSpan StaleAfter => TimeSpan.FromDays(options.Value.StaleAfterDays);

    // ---------------------------------------------------------------- enrollment

    /// <summary>
    /// Registers a machine under its FQDN with a per-machine credential. Never replaces a confirmed machine's
    /// credential just because a request claims its hostname; the only ways to get a credential for an existing
    /// FQDN are (a) a retry carrying the same enrollment nonce while the machine is still unconfirmed (lost
    /// response) or (b) an unexpired, single-use administrator permit.
    /// </summary>
    public async Task<EnrollMachineResult> EnrollAsync(
        string? templateToken, string? hostname, string? nonce, string? agentVersion, string? ip, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(templateToken) || templateToken.Length > MaxSecretLength)
            return new(EnrollMachineStatus.InvalidCredential);

        var templateHash = Secrets.Hash(templateToken);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;

        var template = await db.TemplateCredentials.FirstOrDefaultAsync(t => t.TokenHash == templateHash && t.RevokedUtc == null, ct);
        if (template is null) return new(EnrollMachineStatus.InvalidCredential);

        var nameError = FqdnNormalizer.TryNormalize(hostname, out var fqdn);
        if (nameError is not null) return new(EnrollMachineStatus.InvalidInput, nameError);
        if (nonce is null || !NonceRegex().IsMatch(nonce))
            return new(EnrollMachineStatus.InvalidInput, "An enrollment nonce of 22–128 URL-safe characters is required.");
        var version = CleanVersion(agentVersion);
        var nonceHash = Secrets.Hash(nonce);

        var credential = CredentialPrefix + Secrets.NewToken();
        var credentialHash = Secrets.Hash(credential);

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var machine = await db.Machines.AsNoTracking().FirstOrDefaultAsync(m => m.Fqdn == fqdn, ct);

            if (machine is null)
            {
                var created = new Machine
                {
                    Fqdn = fqdn,
                    CredentialHash = credentialHash,
                    EnrollmentNonceHash = nonceHash,
                    TemplateCredentialId = template.Id,
                    FirstRegisteredUtc = now,
                    CredentialIssuedUtc = now,
                    LastContactUtc = now,
                    LastIp = ip,
                    AgentVersion = version,
                };
                db.Machines.Add(created);
                db.AuditEvents.Add(Audit(MachineAuditActions.MachineRegistered, "machine", $"{fqdn} ({created.Id}) via template credential {template.Name}", now));
                template.LastUsedUtc = now;
                try
                {
                    await db.SaveChangesAsync(ct);
                }
                catch (DbUpdateException ex) when (ex.IsUniqueViolation())
                {
                    // A concurrent enrollment of the same FQDN won the insert; evaluate against its row.
                    db.ChangeTracker.Clear();
                    template = (await db.TemplateCredentials.FirstOrDefaultAsync(t => t.Id == template.Id, ct))!;
                    continue;
                }
                await NotifyAsync(() => events.MachineRegisteredAsync(new MachineEvent(fqdn, ip), ct));
                return new(EnrollMachineStatus.Issued, MachineCredential: credential, Fqdn: fqdn);
            }

            var m = machine;
            var pendingRetry = m.RevokedUtc is null && m.ConfirmedUtc is null && m.EnrollmentNonceHash == nonceHash;
            if (pendingRetry)
            {
                // Same requester retrying after a lost response: re-issue. The WHERE clause makes this race-safe
                // against a concurrent first check-in (which would confirm the machine).
                var n = await db.Machines
                    .Where(x => x.Id == m.Id && x.ConfirmedUtc == null && x.RevokedUtc == null && x.EnrollmentNonceHash == nonceHash)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(x => x.CredentialHash, credentialHash)
                        .SetProperty(x => x.CredentialIssuedUtc, now)
                        .SetProperty(x => x.LastContactUtc, now)
                        .SetProperty(x => x.LastIp, ip)
                        .SetProperty(x => x.AgentVersion, version), ct);
                if (n == 1)
                {
                    await AuditAsync(db, MachineAuditActions.MachineCredentialReissued, "machine", $"{fqdn} ({m.Id}) credential re-issued to the original requester", now, ct);
                    return new(EnrollMachineStatus.Issued, MachineCredential: credential, Fqdn: fqdn);
                }
                continue; // state changed underneath us; re-evaluate
            }

            if (m.ReenrollPermittedUntilUtc is { } until && until > now)
            {
                // The permit is consumed by the update itself, so only one enrollment can use it.
                var n = await db.Machines
                    .Where(x => x.Id == m.Id && x.ReenrollPermittedUntilUtc != null && x.ReenrollPermittedUntilUtc > now)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(x => x.CredentialHash, credentialHash)
                        .SetProperty(x => x.EnrollmentNonceHash, nonceHash)
                        .SetProperty(x => x.CredentialIssuedUtc, now)
                        .SetProperty(x => x.ConfirmedUtc, (DateTime?)null)
                        .SetProperty(x => x.RevokedUtc, (DateTime?)null)
                        .SetProperty(x => x.ReenrollPermittedUntilUtc, (DateTime?)null)
                        .SetProperty(x => x.LastRefusedEnrollUtc, (DateTime?)null)
                        .SetProperty(x => x.LastRefusedEnrollIp, (string?)null)
                        .SetProperty(x => x.TemplateCredentialId, template.Id)
                        .SetProperty(x => x.LastContactUtc, now)
                        .SetProperty(x => x.LastIp, ip)
                        .SetProperty(x => x.AgentVersion, version)
                        .SetProperty(x => x.LastResult, (string?)null)
                        .SetProperty(x => x.LastError, (string?)null), ct);
                if (n == 1)
                {
                    await AuditAsync(db, MachineAuditActions.MachineReenrolled, "machine", $"{fqdn} ({m.Id}) re-enrolled under an administrator permit", now, ct);
                    await NotifyAsync(() => events.MachineRegisteredAsync(new MachineEvent(fqdn, ip), ct));
                    return new(EnrollMachineStatus.Issued, MachineCredential: credential, Fqdn: fqdn);
                }
                continue;
            }

            // Refused. Remember the attempt so the Machines page can show "re-enrollment requested".
            await db.Machines.Where(x => x.Id == m.Id).ExecuteUpdateAsync(s => s
                .SetProperty(x => x.LastRefusedEnrollUtc, now)
                .SetProperty(x => x.LastRefusedEnrollIp, ip), ct);
            var reason = m.RevokedUtc is not null
                ? "This machine was removed by an administrator. An administrator must permit re-enrollment."
                : "A machine with this hostname is already enrolled. An administrator must permit re-enrollment (for example after a rebuild).";
            return new(EnrollMachineStatus.Conflict, reason);
        }

        return new(EnrollMachineStatus.Conflict, "Enrollment is busy for this hostname; retry shortly.");
    }

    // ---------------------------------------------------------------- reporting

    public async Task<CheckInResult> CheckInAsync(string? machineToken, CheckInReport report, string? ip, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(machineToken) || machineToken.Length > MaxSecretLength)
            return new(CheckInStatus.Unauthorized);

        if (report.Result is not ("success" or "error"))
            return new(CheckInStatus.InvalidInput, "result must be 'success' or 'error'.");
        if (report.AppliedEtag is { } etag && (etag.Length > 128 || etag.Any(c => c < ' ' || c > '~')))
            return new(CheckInStatus.InvalidInput, "appliedEtag is not valid.");

        var hash = Secrets.Hash(machineToken);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var m = await db.Machines.FirstOrDefaultAsync(x => x.CredentialHash == hash && x.RevokedUtc == null, ct);
        if (m is null) return new(CheckInStatus.Unauthorized);

        var now = time.GetUtcNow().UtcDateTime;
        var previousIp = m.LastIp;
        m.LastContactUtc = now;
        m.LastIp = ip;
        m.AgentVersion = CleanVersion(report.AgentVersion) ?? m.AgentVersion;
        m.AppliedEtag = string.IsNullOrEmpty(report.AppliedEtag) ? null : report.AppliedEtag;
        m.LastResult = report.Result;
        if (report.Result == "success")
        {
            m.LastSuccessUtc = now;
            m.LastError = null;
        }
        else
        {
            m.LastError = CleanError(report.Error);
        }
        if (m.ConfirmedUtc is null)
        {
            m.ConfirmedUtc = now;          // the agent really holds the credential now
            m.EnrollmentNonceHash = null;  // the nonce has done its job
        }
        await db.SaveChangesAsync(ct);

        if (previousIp != ip)
            await NotifyAsync(() => events.MachineIpChangedAsync(new MachineEvent(m.Fqdn, ip, previousIp), ct));
        return new(CheckInStatus.Ok);
    }

    // ---------------------------------------------------------------- admin

    public async Task<List<MachineView>> ListAsync(bool includeRevoked = true, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var rows = await db.Machines.AsNoTracking()
            .Where(m => includeRevoked || m.RevokedUtc == null)
            .OrderBy(m => m.Fqdn)
            .ToListAsync(ct);
        return rows.Select(m =>
        {
            var status = MachineStatusCalculator.Compute(m, now, StaleAfter);
            return new MachineView(
                m, status, MachineStatusCalculator.Describe(m, status),
                ReenrollRequested: m.LastRefusedEnrollUtc is not null,
                PermitActive: m.ReenrollPermittedUntilUtc > now);
        }).ToList();
    }

    /// <summary>
    /// Disables the machine's reporting credential. It does not touch SSH keys or anything on the machine itself.
    /// The row stays as a tombstone that blocks silent re-enrollment.
    /// </summary>
    public async Task<bool> RevokeAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var m = await db.Machines.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (m is null) return false;
        if (m.RevokedUtc is not null) return true;
        m.RevokedUtc = now;
        m.CredentialHash = null;
        m.EnrollmentNonceHash = null;
        m.ReenrollPermittedUntilUtc = null;
        db.AuditEvents.Add(Audit(MachineAuditActions.MachineRevoked, actor, $"{m.Fqdn} ({m.Id}) reporting credential disabled", now));
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Allows exactly one enrollment under this hostname (e.g. a rebuilt container) within a short window.</summary>
    public async Task<bool> PermitReenrollAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var m = await db.Machines.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (m is null) return false;
        m.ReenrollPermittedUntilUtc = now.AddMinutes(options.Value.ReenrollPermitMinutes);
        db.AuditEvents.Add(Audit(MachineAuditActions.MachineReenrollPermitted, actor, $"{m.Fqdn} ({m.Id}) until {m.ReenrollPermittedUntilUtc:u}", now));
        await db.SaveChangesAsync(ct);
        return true;
    }

    // ---------------------------------------------------------------- helpers

    private static string? CleanVersion(string? v) => v is not null && VersionRegex().IsMatch(v) ? v : null;

    private static string? CleanError(string? error)
    {
        if (string.IsNullOrWhiteSpace(error)) return "unspecified error";
        var cleaned = new string(error.Select(c => char.IsControl(c) ? ' ' : c).ToArray()).Trim();
        return cleaned.Length > 500 ? cleaned[..500] : cleaned;
    }

    private static AuditEvent Audit(string action, string actor, string detail, DateTime now) =>
        new() { TimestampUtc = now, Action = action, Actor = actor, Detail = detail };

    private static async Task AuditAsync(AppDbContext db, string action, string actor, string detail, DateTime now, CancellationToken ct)
    {
        db.AuditEvents.Add(Audit(action, actor, detail, now));
        await db.SaveChangesAsync(ct);
    }

    private async Task NotifyAsync(Func<Task> call)
    {
        try { await call(); }
        catch (Exception ex) { log.LogWarning(ex, "Machine event sink failed; ignoring."); }
    }
}

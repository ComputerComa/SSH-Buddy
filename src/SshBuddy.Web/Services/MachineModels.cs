using SshBuddy.Web.Data;

namespace SshBuddy.Web.Services;

public class MachineOptions
{
    /// <summary>A machine with no contact for this long is shown as stale.</summary>
    public double StaleAfterDays { get; set; } = 3;

    /// <summary>How long an administrator's "permit re-enrollment" stays usable.</summary>
    public int ReenrollPermitMinutes { get; set; } = 240;
}

public enum MachineStatus { Healthy, SyncError, Stale, Revoked }

public static class MachineStatusCalculator
{
    /// <summary>
    /// Stale beats everything (no recent contact, whatever it last said). A machine that checks in but cannot
    /// sync, or has never reported a successful sync, is a sync error — never healthy.
    /// </summary>
    public static MachineStatus Compute(Machine m, DateTime nowUtc, TimeSpan staleAfter)
    {
        if (m.RevokedUtc is not null) return MachineStatus.Revoked;
        if (nowUtc - m.LastContactUtc > staleAfter) return MachineStatus.Stale;
        if (m.LastResult != "success" || m.LastSuccessUtc is null) return MachineStatus.SyncError;
        return MachineStatus.Healthy;
    }

    public static string Describe(Machine m, MachineStatus status) => status switch
    {
        MachineStatus.Revoked => "Reporting disabled by an administrator.",
        MachineStatus.Stale => "No contact within the stale threshold.",
        MachineStatus.SyncError when m.LastResult is null => "Enrolled; no report received yet.",
        MachineStatus.SyncError when m.LastResult == "success" => "No successful sync recorded yet.",
        MachineStatus.SyncError => m.LastError ?? "The last sync failed.",
        _ => "Key list applied.",
    };
}

public sealed record MachineView(Machine Machine, MachineStatus Status, string StatusDetail, bool ReenrollRequested, bool PermitActive);

public sealed record MachineEvent(string Fqdn, string? Ip, string? PreviousIp = null);

/// <summary>
/// Extension point for later server-side integrations (DNS registration, new-machine notification).
/// Called after the database change is committed; failures are logged and never affect the agent's request.
/// </summary>
public interface IMachineEventSink
{
    Task MachineRegisteredAsync(MachineEvent e, CancellationToken ct);
    Task MachineIpChangedAsync(MachineEvent e, CancellationToken ct);
}

public sealed class NullMachineEventSink : IMachineEventSink
{
    public Task MachineRegisteredAsync(MachineEvent e, CancellationToken ct) => Task.CompletedTask;
    public Task MachineIpChangedAsync(MachineEvent e, CancellationToken ct) => Task.CompletedTask;
}

public enum EnrollMachineStatus { Issued, InvalidCredential, InvalidInput, Conflict }

public sealed record EnrollMachineResult(EnrollMachineStatus Status, string? Error = null, string? MachineCredential = null, string? Fqdn = null);

public sealed record CheckInReport(string? AgentVersion, string? Result, string? Error, string? AppliedEtag);

public enum CheckInStatus { Ok, Unauthorized, InvalidInput }

public sealed record CheckInResult(CheckInStatus Status, string? Error = null);

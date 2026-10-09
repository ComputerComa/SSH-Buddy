using System.Globalization;

namespace SshBuddy.Web.Services;

/// <summary>
/// Canonical form of a machine's FQDN, the unique machine identifier. The server is authoritative: the agent
/// applies similar rules but nothing it sends is trusted without passing through here.
/// </summary>
public static class FqdnNormalizer
{
    public const int MaxLength = 253;
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = true };

    /// <summary>Returns null error and the normalized name, or an error message.</summary>
    public static string? TryNormalize(string? input, out string fqdn)
    {
        fqdn = "";
        if (string.IsNullOrWhiteSpace(input)) return "A hostname is required.";
        var s = input.Trim();
        if (s.EndsWith('.')) s = s[..^1];           // one trailing root dot
        if (s.Length == 0 || s.Length > 1000) return "The hostname is not valid.";
        if (s.Any(c => char.IsControl(c) || char.IsWhiteSpace(c))) return "The hostname contains whitespace or control characters.";

        try { s = Idn.GetAscii(s); }
        catch (ArgumentException) { return "The hostname is not a valid domain name."; }
        s = s.ToLowerInvariant();

        if (s.Length > MaxLength) return "The hostname is too long.";
        var labels = s.Split('.');
        if (labels.Length < 2) return "A fully qualified hostname (with a domain) is required.";
        foreach (var l in labels)
        {
            if (l.Length is 0 or > 63) return "The hostname has an empty or over-long label.";
            if (l[0] == '-' || l[^1] == '-') return "Hostname labels cannot start or end with '-'.";
            if (!l.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
                return "Hostname labels may contain only letters, digits and '-'.";
        }
        if (labels[^1].All(char.IsAsciiDigit)) return "The last hostname label cannot be all digits (looks like an IP address).";

        fqdn = s;
        return null;
    }
}

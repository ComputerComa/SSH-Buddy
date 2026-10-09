namespace SshBuddy.Web.Services;

public static class KeyLabel
{
    public const int MaxLength = 64;

    /// <summary>Trims and validates a device label. Returns null error when valid.</summary>
    public static string? Validate(string? label, out string normalized)
    {
        normalized = label?.Trim() ?? "";
        if (normalized.Length == 0) return "A device label is required.";
        if (normalized.Length > MaxLength) return $"The device label must be at most {MaxLength} characters.";
        if (normalized.Any(char.IsControl)) return "The device label contains control characters.";
        return null;
    }

    /// <summary>
    /// Label rendered as an authorized_keys comment: printable ASCII only, no whitespace.
    /// The sync client's line validator accepts exactly this alphabet.
    /// </summary>
    public static string ToComment(string label)
    {
        var chars = label.Select(c => c is >= '!' and <= '~' ? c : '_').ToArray();
        return chars.Length == 0 ? "key" : new string(chars);
    }
}

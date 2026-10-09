using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace SshBuddy.Web.Services;

public class AgentOptions
{
    /// <summary>Directory holding one sub-directory per version (see agent/build.sh).</summary>
    public string ReleaseDirectory { get; set; } = "App_Data/agent";

    /// <summary>Serve this version instead of the highest complete one.</summary>
    public string? Version { get; set; }
}

public sealed record AgentBinary(string Platform, long Size, string Sha256, string Path);

public sealed record AgentManifest(string Version, IReadOnlyList<AgentBinary> Binaries)
{
    /// <summary>
    /// Line format for the shell bootstrap, which has no JSON parser:
    /// <c>version platform size sha256 path</c>, one binary per line. Rendered from the same object as the JSON.
    /// </summary>
    public string ToText()
    {
        var sb = new StringBuilder();
        foreach (var b in Binaries)
            sb.Append(Version).Append(' ').Append(b.Platform).Append(' ').Append(b.Size).Append(' ').Append(b.Sha256).Append(' ').Append(b.Path).Append('\n');
        return sb.ToString();
    }
}

/// <summary>
/// Serves only complete releases: every supported platform binary present and matching the SHA256SUMS written by
/// the build. A checksum served from the same host as the binary is an integrity check against corruption and
/// partial uploads, not an independent signature; authenticity rests on TLS to this server.
/// </summary>
public partial class AgentReleaseService(IOptions<AgentOptions> options)
{
    public static readonly string[] Platforms = ["linux-amd64", "linux-arm64"];
    private const string FilePrefix = "ssh-buddy-agent-";

    [GeneratedRegex(@"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")]
    private static partial Regex VersionRegex();

    private readonly ConcurrentDictionary<string, (long Size, DateTime Mtime, string Sha)> _hashCache = new();

    public AgentManifest? GetManifest()
    {
        var root = options.Value.ReleaseDirectory;
        if (!Directory.Exists(root)) return null;

        var complete = new List<(string Version, AgentManifest Manifest)>();
        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            var version = System.IO.Path.GetFileName(dir);
            if (!VersionRegex().IsMatch(version)) continue;
            var manifest = Load(dir, version);
            if (manifest is not null) complete.Add((version, manifest));
        }

        if (!string.IsNullOrEmpty(options.Value.Version))
            return complete.FirstOrDefault(c => c.Version == options.Value.Version).Manifest;

        return complete.OrderByDescending(c => c.Version, Comparer<string>.Create(CompareVersions)).Select(c => c.Manifest).FirstOrDefault();
    }

    /// <summary>Returns the file for a complete release, or null (unknown/incomplete version, bad platform).</summary>
    public (string FilePath, long Size)? Find(string version, string platform)
    {
        if (!VersionRegex().IsMatch(version) || !Platforms.Contains(platform)) return null;
        var dir = System.IO.Path.Combine(options.Value.ReleaseDirectory, version);
        if (Load(dir, version) is null) return null;
        var file = System.IO.Path.Combine(dir, FilePrefix + platform);
        return (file, new FileInfo(file).Length);
    }

    private AgentManifest? Load(string dir, string version)
    {
        var sums = System.IO.Path.Combine(dir, "SHA256SUMS");
        if (!File.Exists(sums)) return null;

        var declared = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(sums))
        {
            var parts = line.Split("  ", 2);
            if (parts.Length == 2 && parts[0].Length == 64) declared[parts[1].Trim()] = parts[0].ToLowerInvariant();
        }

        var binaries = new List<AgentBinary>();
        foreach (var platform in Platforms)
        {
            var name = FilePrefix + platform;
            var path = System.IO.Path.Combine(dir, name);
            var info = new FileInfo(path);
            if (!info.Exists || info.Length == 0) return null;
            var actual = HashOf(info);
            if (!declared.TryGetValue(name, out var expected) || expected != actual) return null;
            binaries.Add(new AgentBinary(platform, info.Length, actual, $"/api/agent/download/{version}/{platform}"));
        }
        return new AgentManifest(version, binaries);
    }

    private string HashOf(FileInfo f)
    {
        if (_hashCache.TryGetValue(f.FullName, out var c) && c.Size == f.Length && c.Mtime == f.LastWriteTimeUtc) return c.Sha;
        using var s = f.OpenRead();
        var sha = Convert.ToHexStringLower(SHA256.HashData(s));
        _hashCache[f.FullName] = (f.Length, f.LastWriteTimeUtc, sha);
        return sha;
    }

    private static int CompareVersions(string? a, string? b)
    {
        var ma = VersionRegex().Match(a ?? ""); var mb = VersionRegex().Match(b ?? "");
        for (var i = 1; i <= 3; i++)
        {
            var c = int.Parse(ma.Groups[i].Value).CompareTo(int.Parse(mb.Groups[i].Value));
            if (c != 0) return c;
        }
        var pa = ma.Groups[4].Value; var pb = mb.Groups[4].Value;
        if (pa == pb) return 0;
        if (pa.Length == 0) return 1;   // a release outranks its prereleases
        if (pb.Length == 0) return -1;
        return string.CompareOrdinal(pa, pb);
    }
}

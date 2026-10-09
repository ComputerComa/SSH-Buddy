using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SshBuddy.Web.Services;

public sealed record ParsedPublicKey(string Algorithm, string KeyMaterial, string Fingerprint);

public sealed record KeyParseResult(ParsedPublicKey? Key, string? Error)
{
    public bool IsValid => Key is not null;
}

/// <summary>
/// Strict parser for a single OpenSSH public key line ("algorithm base64 [comment]").
/// Only the algorithm and key blob are kept; the comment is discarded, so nothing
/// attacker-controlled can reach an authorized_keys line except the validated blob.
///
/// It must accept exactly what the Go agent's golang.org/x/crypto/ssh parser accepts (never more): the agent
/// rejects a whole key list if any line fails, so a key stored here that the agent refuses would stop every
/// machine from receiving updates and revocations. testdata/key-corpus.txt, shared with the agent's tests, enforces this.
/// </summary>
public static partial class PublicKeyParser
{
    public const int MaxInputLength = 8192;
    public const int MinRsaBits = 2048;
    private const int MaxRsaBits = 16384;

    private static readonly HashSet<string> Algorithms = new(StringComparer.Ordinal)
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    };

    [GeneratedRegex("^[A-Za-z0-9+/]+={0,2}$")]
    private static partial Regex Base64Regex();

    public static KeyParseResult Parse(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return Fail("A public key is required.");
        if (input.Length > MaxInputLength) return Fail("The public key input is too long.");

        if (input.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase)
            || input.Contains("PuTTY-User-Key-File", StringComparison.OrdinalIgnoreCase))
            return Fail("That looks like a private key. Never submit private keys; submit the .pub file only.");

        // Tolerate exactly one trailing newline (the usual end of a .pub file).
        if (input.EndsWith("\r\n", StringComparison.Ordinal)) input = input[..^2];
        else if (input.EndsWith('\n')) input = input[..^1];

        if (input.Contains('\n') || input.Contains('\r'))
            return Fail("The public key must be a single line.");
        if (input.Any(char.IsControl))
            return Fail("The public key contains control characters.");

        var parts = input.Trim(' ').Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return Fail("Expected the form: <algorithm> <base64-key> [comment].");

        var algorithm = parts[0];
        if (!Algorithms.Contains(algorithm))
            return Fail("Unsupported key type. authorized_keys options, certificates and other formats are not accepted.");

        var b64 = parts[1];
        if (!Base64Regex().IsMatch(b64) || b64.Length % 4 != 0)
            return Fail("The key data is not valid base64.");

        byte[] blob;
        try { blob = Convert.FromBase64String(b64); }
        catch (FormatException) { return Fail("The key data is not valid base64."); }
        if (Convert.ToBase64String(blob) != b64)
            return Fail("The key data is not canonical base64.");

        var error = ValidateBlob(algorithm, blob);
        if (error is not null) return Fail(error);

        var fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
        return new KeyParseResult(new ParsedPublicKey(algorithm, b64, fingerprint), null);
    }

    private static KeyParseResult Fail(string error) => new(null, error);

    private static string? ValidateBlob(string algorithm, byte[] blob)
    {
        const string Malformed = "The key data is malformed for its declared key type.";
        var r = new BlobReader(blob);
        if (!r.TryReadString(out var typeBytes) || !typeBytes.SequenceEqual(System.Text.Encoding.ASCII.GetBytes(algorithm)))
            return "The key data does not match the declared key type.";

        switch (algorithm)
        {
            case "ssh-ed25519":
                if (!r.TryReadString(out var ed) || ed.Length != 32) return Malformed;
                break;

            case "ssh-rsa":
                if (!r.TryReadString(out var e) || !r.TryReadString(out var n)) return Malformed;
                // SSH mpints must be positive and minimally encoded; x/crypto re-marshals and compares, so a
                // redundant leading zero (or a "negative" value) makes the agent reject the key.
                if (!IsMinimalPositiveMpint(e) || !IsMinimalPositiveMpint(n)) return Malformed;
                var exponent = new BigInteger(e, isUnsigned: true, isBigEndian: true);
                // x/crypto: the exponent must be odd, at least 3, and at most 24 bits.
                if (exponent < 3 || exponent.IsEven || BitLength(e) > 24) return Malformed;
                var bits = BitLength(n);
                if (bits < MinRsaBits) return $"RSA keys must be at least {MinRsaBits} bits.";
                if (bits > MaxRsaBits) return Malformed;
                break;

            case "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521":
                var curve = algorithm["ecdsa-sha2-".Length..];
                if (!ReadCurveAndPoint(ref r, curve)) return Malformed;
                break;

            case "sk-ssh-ed25519@openssh.com":
                if (!r.TryReadString(out var sked) || sked.Length != 32 || !r.TryReadString(out _)) return Malformed;
                break;

            case "sk-ecdsa-sha2-nistp256@openssh.com":
                if (!ReadCurveAndPoint(ref r, "nistp256") || !r.TryReadString(out _)) return Malformed;
                break;
        }

        return r.AtEnd ? null : Malformed;
    }

    private static bool ReadCurveAndPoint(ref BlobReader r, string curve)
    {
        if (!r.TryReadString(out var c) || System.Text.Encoding.ASCII.GetString(c) != curve) return false;
        if (!r.TryReadString(out var point)) return false;
        var size = curve switch { "nistp256" => 32, "nistp384" => 48, _ => 66 };
        if (point.Length != 1 + 2 * size || point[0] != 0x04) return false;   // uncompressed points only
        return IsOnCurve(curve,
            new BigInteger(point.AsSpan(1, size), isUnsigned: true, isBigEndian: true),
            new BigInteger(point.AsSpan(1 + size, size), isUnsigned: true, isBigEndian: true));
    }

    // Short Weierstrass y^2 = x^3 - 3x + b (mod p). Exact arithmetic, so no dependency on the platform's crypto library.
    private static readonly Dictionary<string, (BigInteger P, BigInteger B)> Curves = new()
    {
        ["nistp256"] = (Hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
                        Hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")),
        ["nistp384"] = (Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
                        Hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")),
        ["nistp521"] = ((BigInteger.One << 521) - 1,
                        Hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")),
    };

    private static BigInteger Hex(string h) => BigInteger.Parse("0" + h, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static bool IsOnCurve(string curve, BigInteger x, BigInteger y)
    {
        var (p, b) = Curves[curve];
        if (x >= p || y >= p) return false;
        var left = y * y % p;
        var right = ((x * x % p * x - 3 * x + b) % p + p) % p;
        return left == right;
    }

    /// <summary>Positive, non-zero, with no redundant leading 0x00 and no unnecessary sign handling.</summary>
    private static bool IsMinimalPositiveMpint(byte[] v)
    {
        if (v.Length == 0) return false;                              // zero
        if ((v[0] & 0x80) != 0) return false;                         // negative
        if (v[0] == 0) return v.Length > 1 && (v[1] & 0x80) != 0;     // a leading zero is only allowed to protect a high bit
        return true;
    }

    private static int BitLength(byte[] mpint)
    {
        var i = 0;
        while (i < mpint.Length && mpint[i] == 0) i++;
        if (i == mpint.Length) return 0;
        return (mpint.Length - i - 1) * 8 + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)mpint[i]));
    }

    private ref struct BlobReader(byte[] data)
    {
        private int _pos;
        public readonly bool AtEnd => _pos == data.Length;

        public bool TryReadString(out byte[] value)
        {
            value = [];
            if (data.Length - _pos < 4) return false;
            var len = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_pos, 4));
            if (len > data.Length - _pos - 4) return false;
            value = data.AsSpan(_pos + 4, (int)len).ToArray();
            _pos += 4 + (int)len;
            return true;
        }
    }
}

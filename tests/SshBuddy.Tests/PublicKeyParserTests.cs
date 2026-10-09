using SshBuddy.Tests.Support;
using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

public class PublicKeyParserTests
{
    [Theory]
    [InlineData(Fixtures.Ed25519, "ssh-ed25519", Fixtures.Ed25519Fingerprint)]
    [InlineData(Fixtures.Rsa3072, "ssh-rsa", Fixtures.Rsa3072Fingerprint)]
    [InlineData(Fixtures.Ecdsa256, "ecdsa-sha2-nistp256", Fixtures.Ecdsa256Fingerprint)]
    [InlineData(Fixtures.Ecdsa384, "ecdsa-sha2-nistp384", Fixtures.Ecdsa384Fingerprint)]
    [InlineData(Fixtures.Ecdsa521, "ecdsa-sha2-nistp521", Fixtures.Ecdsa521Fingerprint)]
    public void Accepts_real_keys_and_matches_ssh_keygen_fingerprint(string line, string algorithm, string fingerprint)
    {
        var r = PublicKeyParser.Parse(line);
        Assert.True(r.IsValid, r.Error);
        Assert.Equal(algorithm, r.Key!.Algorithm);
        Assert.Equal(fingerprint, r.Key.Fingerprint);
    }

    [Fact]
    public void Accepts_security_key_types() =>
        Assert.True(PublicKeyParser.Parse(Fixtures.SkEd25519()).IsValid);

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void Tolerates_exactly_one_trailing_newline(string nl) =>
        Assert.True(PublicKeyParser.Parse(Fixtures.Ed25519 + nl).IsValid);

    [Fact]
    public void Comment_is_optional_and_does_not_change_key_material()
    {
        var withComment = PublicKeyParser.Parse(Fixtures.Ed25519).Key!;
        var without = PublicKeyParser.Parse("ssh-ed25519 " + Fixtures.Ed25519Blob).Key!;
        var other = PublicKeyParser.Parse("ssh-ed25519 " + Fixtures.Ed25519Blob + " totally different comment").Key!;
        Assert.Equal(withComment.KeyMaterial, without.KeyMaterial);
        Assert.Equal(withComment.KeyMaterial, other.KeyMaterial);
    }

    [Fact]
    public void Rejects_private_keys()
    {
        var r = PublicKeyParser.Parse(Fixtures.PrivateKey);
        Assert.False(r.IsValid);
        Assert.Contains("private key", r.Error, StringComparison.OrdinalIgnoreCase);
    }

    public static TheoryData<string> Malformed => new()
    {
        "",
        "   ",
        "ssh-ed25519",
        "ssh-ed25519 ",
        // authorized_keys options and other injection attempts
        "command=\"/bin/evil\" " + Fixtures.Ed25519,
        "no-pty,from=\"1.2.3.4\" " + Fixtures.Ed25519,
        "restrict " + Fixtures.Ed25519,
        // multiline / embedded control characters
        Fixtures.Ed25519 + "\n" + Fixtures.Ed25519Other,
        Fixtures.Ed25519 + "\n\n",
        Fixtures.Ed25519 + "\rcommand=\"x\" " + Fixtures.Ed25519Other,
        Fixtures.Ed25519 + "\0",
        Fixtures.Ed25519.Replace(" ", "\t"),
        // unsupported formats
        "ssh-dss AAAAB3NzaC1kc3MAAACBAP== x",
        "ssh-ed25519-cert-v01@openssh.com " + Fixtures.Ed25519Blob,
        // broken base64 / structure
        "ssh-ed25519 !!!notbase64!!!",
        "ssh-ed25519 " + Fixtures.Ed25519Blob[..^4],
        "ssh-ed25519 " + Fixtures.Ed25519Blob + "AAAA",
        "ssh-ed25519 " + Fixtures.Ed25519Blob.TrimEnd('c') + "=",
        // declared type does not match the blob
        "ssh-rsa " + Fixtures.Ed25519Blob,
        // weak RSA
        Fixtures.Rsa1024,
        // curve/algorithm mismatch
        "ecdsa-sha2-nistp384 " + Fixtures.Ecdsa256.Split(' ')[1],
        new string('A', PublicKeyParser.MaxInputLength + 1),
    };

    [Theory]
    [MemberData(nameof(Malformed))]
    public void Rejects_malformed_input(string input)
    {
        var r = PublicKeyParser.Parse(input);
        Assert.False(r.IsValid);
        Assert.False(string.IsNullOrEmpty(r.Error));
    }

    [Fact]
    public void Rejects_trailing_bytes_inside_the_blob()
    {
        var blob = Fixtures.Blob(Fixtures.Ascii("ssh-ed25519"), new byte[32]).Concat(new byte[] { 1, 2, 3, 4 }).ToArray();
        Assert.False(PublicKeyParser.Parse("ssh-ed25519 " + Convert.ToBase64String(blob)).IsValid);
    }

    [Fact]
    public void Rejects_wrong_length_ed25519_key()
    {
        var blob = Fixtures.Blob(Fixtures.Ascii("ssh-ed25519"), new byte[31]);
        Assert.False(PublicKeyParser.Parse("ssh-ed25519 " + Convert.ToBase64String(blob)).IsValid);
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("laptop", true)]
    [InlineData("a\nb", false)]
    public void Label_validation(string label, bool ok) =>
        Assert.Equal(ok, KeyLabel.Validate(label, out _) is null);

    [Fact]
    public void Label_comment_is_always_printable_ascii_without_spaces()
    {
        var comment = KeyLabel.ToComment("Wälker's Laptop 🙂 \"x\"");
        Assert.Matches("^[!-~]+$", comment);
    }
}

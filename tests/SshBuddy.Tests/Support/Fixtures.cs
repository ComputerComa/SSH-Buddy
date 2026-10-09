using System.Buffers.Binary;
using System.Text;

namespace SshBuddy.Tests.Support;

/// <summary>Real keys generated with ssh-keygen; fingerprints are `ssh-keygen -lf` output.</summary>
public static class Fixtures
{
    public const string Ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMgXTvJTR9gazAPocNC4rL8cutrwxP4HUcSYPQAmkdoc alice@laptop";
    public const string Ed25519Fingerprint = "SHA256:gZDwIlFyJUsv3SZrSLW/QYwi2MQFMTwKTlrBqPloFkw";
    public const string Ed25519Blob = "AAAAC3NzaC1lZDI1NTE5AAAAIMgXTvJTR9gazAPocNC4rL8cutrwxP4HUcSYPQAmkdoc";

    public const string Ed25519Other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIES06xsqQXHq7oscHhCzOk6qP/zPtkO/quGMqUoEXuFI bob";

    public const string Rsa3072 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGjJk8Sc9m28tHvNtxr6/m00nC9qG7U4W6nzcYzPWrQSF6dASQ6KPt6ka7FGvu9nWRt3rJbnvdVW1vmF888dR99x4R9TJVl+RtSes9ky+1oN8W490CSj5iJeggGHQrf1XEw6eaQjHfKyYx8/5nDw4IXkU6NvA8UGOqpsy7c2MeHThScjMYKHiQaOZ1oD1We0o8BusKVIJO/jcDicqiz2BPgVgyIG4538C1F6FxUYIrf78hyyKs57FZIFSy746f0evo1+muzpPY3fSePelhT/W5CyF192b5WI38Dr/Ceg1o7sJa2ikhHChv9kc6IAL7x3gR2GU5XGWdoB4cODdC6lVcGBXA7uercV0BntO2Q4+RDSjpXSGfTzLi9P8V0RhnOCd/gEOzVDIcPugEP2A2GNN4sJtcu2btU0XvMW0r7UQiuj6stwXCo1OpPmjmbWVYqeJ5G/uBdXZvd4SOnZvMhNmwLsFmS6YYzv/uX/Po55gFESURJiTsmDhCwD/kz3vnCLE= rsa key";
    public const string Rsa3072Fingerprint = "SHA256:LhwWSCBgjImptgebpnhO1thhOxTeEGAjrfxETHDQp8o";

    public const string Rsa1024 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDAouNKRGhc5MHJeDKEZdU1W1g5CDobXXhq2DN8Tz4SGSOTUfUrJmK4e77btshZtxSUg3Q7dlh83Jpj6cM+BjmN3VYmxO4FqiwmkGcjvm9dXZGVmi1vtqbC22ivHc2GpytvZuUBJi4zfDPmoG5iODRzOGfsAoyCVptKbhaZGC3/MQ== weak";

    public const string Ecdsa256 = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNTttKhExTHhIw3Bagauf59hintDCcKnXF0dLQXM9DzmGm+jxOC3dCdCNdF4udLh1PaTVx7h49fXQPa2MU5U2Ow= ec256";
    public const string Ecdsa256Fingerprint = "SHA256:8WX1fEerr0ungWD0hNTXf08pY70CVaD5lW82Zd1iG28";
    public const string Ecdsa384 = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJu8CVV/xVtqKGeEkOuz9U04rb74S+BTdB4FQPDpogPAIDqXgO5dlWsQnhwKke+qq4Ygy4L7TVdhiDwmsddmGDjZ6R74WzdQO7qLLOEw6HNqbCtnt4Lh25+VpFSiN4NQCQ== ec384";
    public const string Ecdsa384Fingerprint = "SHA256:jBQDTpVuzmKh52Rbt5z4CW5O78eLJ58FqXBM72FTDPc";
    public const string Ecdsa521 = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBABSQZM9MTeEHCLc0JDfuGXsn8/C6Vc8+wXQC2qLwbQc4Vt76cVdk1lcB+ddrLF/Zu199iTDAqYouC5N0QMktDMKIwCZ/yriBekCajorf/L26bBWw7xDl90ERHcU8/oMo1u7lQjIbfMWL7wSYLhMykDoC8CXUQUcmseaayC7aZo29IjrKA== ec521";
    public const string Ecdsa521Fingerprint = "SHA256:4FKu8eDNY8M5CvgkWnbWaMqjvP9S4HXChZkEJtinwrs";

    public const string PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n";

    /// <summary>Builds an SSH wire-format blob: each part is a uint32 length-prefixed string.</summary>
    public static byte[] Blob(params byte[][] parts)
    {
        using var ms = new MemoryStream();
        foreach (var p in parts)
        {
            var len = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(len, (uint)p.Length);
            ms.Write(len);
            ms.Write(p);
        }
        return ms.ToArray();
    }

    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    /// <summary>A structurally valid sk-ssh-ed25519 key (hardware keys cannot be generated in CI).</summary>
    public static string SkEd25519(byte fill = 7) =>
        "sk-ssh-ed25519@openssh.com " + Convert.ToBase64String(
            Blob(Ascii("sk-ssh-ed25519@openssh.com"), Enumerable.Repeat(fill, 32).ToArray(), Ascii("ssh:"))) + " yubikey";

    /// <summary>A fresh, unique, valid ed25519 key.</summary>
    public static string RandomEd25519(string comment = "gen")
    {
        var key = new byte[32];
        Random.Shared.NextBytes(key);
        return "ssh-ed25519 " + Convert.ToBase64String(Blob(Ascii("ssh-ed25519"), key)) + " " + comment;
    }
}

using SshBuddy.Web.Services;

namespace SshBuddy.Tests;

/// <summary>
/// Contract between the server and the Go agent. The agent rejects a whole key list if any line fails its parser,
/// so a key the server accepts but the agent rejects would stop every machine from receiving revocations.
/// The corpus (testdata/key-corpus.txt) is shared with the Go suite; its verdicts are the agent's.
/// </summary>
public class KeyCorpusTests
{
    private static string CorpusPath()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "global.json"))) d = d.Parent;
        return Path.Combine(d!.FullName, "testdata", "key-corpus.txt");
    }

    public static TheoryData<string, string, string> Cases()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var raw in File.ReadAllLines(CorpusPath()))
        {
            if (raw.Length == 0 || raw[0] == '#') continue;
            var parts = raw.Split('|', 3);
            data.Add(parts[0], parts[1], parts[2]);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Server_and_agent_agree_on_every_key_in_the_corpus(string agentVerdict, string name, string line)
    {
        var server = PublicKeyParser.Parse(line);
        var serverVerdict = server.IsValid ? "accept" : "reject";
        Assert.True(serverVerdict == agentVerdict,
            $"'{name}': the agent says {agentVerdict} but the server says {serverVerdict}" +
            (server.IsValid ? "" : $" ({server.Error})") +
            (agentVerdict == "reject" ? ". A key the server stores but the agent rejects would block key-list updates fleet-wide." : "."));
    }

    [Fact]
    public void The_corpus_is_substantial()
    {
        var accept = Cases().Select(c => (string)c[0]).Count(v => v == "accept");
        var reject = Cases().Select(c => (string)c[0]).Count(v => v == "reject");
        Assert.True(accept >= 8 && reject >= 30, $"accept={accept} reject={reject}");
    }
}

namespace SshBuddy.Web.Services;

public static class EnrollmentCommand
{
    /// <summary>
    /// Builds the curl command shown to the administrator. The token travels in the Authorization
    /// header; the .pub file is read and URL-encoded by curl itself.
    /// </summary>
    public static string Build(string baseUrl, string token) =>
        $"curl --fail-with-body --silent --show-error --request POST \"{baseUrl.TrimEnd('/')}/api/keys/enroll\" "
        + $"--header \"Authorization: Bearer {token}\" "
        + "--data-urlencode \"label=$(hostname)\" "
        + "--data-urlencode \"publicKey@$HOME/.ssh/id_ed25519.pub\"";
}

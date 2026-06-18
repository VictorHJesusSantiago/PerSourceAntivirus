using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

public class HoneypotManager : IHoneypotManager
{
    private static readonly string[] WatchDirectories =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
    ];

    private static readonly Dictionary<string, string> DecoyContents = new()
    {
        ["passwords.txt"]      = "admin:Summer2024!\nbackup:Backup@2024\nservice:P@ssw0rd123\n",
        ["wallet.dat"]         = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKp9VQBkcFjQZFJ8zQk4NLr6ZFHJ3DTMpNqEnLFEBKHJ7hBi5mWHKk4kZGGFbp6gGRBbS8WHEWgmJm\n",
        ["backup_keys.txt"]    = "AAAA-BBBB-CCCC-DDDD-EEEE\nFFFF-0000-1111-2222-3333\nRecovery: ZZZZ-YYYY-XXXX-WWWW\n",
        ["confidential.xlsx"]  = "Employee,Department,Salary\nJohn Doe,Engineering,95000\nJane Smith,Finance,88000\n",
        ["ssh_private_key.txt"] = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAkGS2rTfake+key+data+not+real\n-----END RSA PRIVATE KEY-----\n",
    };

    public async Task<IReadOnlyList<string>> SetupHoneypotsAsync(CancellationToken ct = default)
    {
        var created = new List<string>();
        foreach (var dir in WatchDirectories)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var (filename, content) in DecoyContents)
            {
                var path = Path.Combine(dir, $"_psav_decoy_{filename}");
                await File.WriteAllTextAsync(path, content, ct);
                try { File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System); }
                catch { /* non-fatal if attributes can't be set */ }
                created.Add(path);
            }
        }
        return created;
    }
}

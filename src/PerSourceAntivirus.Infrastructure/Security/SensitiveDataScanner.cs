using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class SensitiveDataScanner : ISensitiveDataScanner
{
    private static readonly string[] SupportedExtensions =
    [
        ".txt", ".log", ".env", ".ini", ".cfg", ".config", ".json", ".yaml", ".yml",
        ".xml", ".sh", ".bat", ".ps1", ".py", ".rb", ".php", ".js", ".ts", ".cs",
        ".java", ".go", ".properties", ".conf", ".key", ".pem", ".crt", ".pfx",
        ".bak", ".sql", ".csv"
    ];

    private static readonly (string DataType, Regex Pattern, int Severity)[] Patterns =
    [
        ("CreditCard",      new Regex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", RegexOptions.Compiled), 8),
        ("CPF",             new Regex(@"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", RegexOptions.Compiled), 6),
        ("AwsAccessKey",    new Regex(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled), 9),
        ("AwsSecretKey",    new Regex(@"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*[""']?[A-Za-z0-9/+]{40}[""']?", RegexOptions.Compiled), 9),
        ("SshPrivateKey",   new Regex(@"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", RegexOptions.Compiled), 9),
        ("PgpPrivateKey",   new Regex(@"-----BEGIN PGP PRIVATE KEY BLOCK-----", RegexOptions.Compiled), 9),
        ("GitHubToken",     new Regex(@"\bghp_[A-Za-z0-9]{36}\b|\bgh[orsu]_[A-Za-z0-9_]{36,}\b", RegexOptions.Compiled), 6),
        ("SlackToken",      new Regex(@"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b", RegexOptions.Compiled), 6),
        ("PlainPassword",   new Regex(@"(?i)(?:password|passwd|pwd)\s*[=:]\s*[""']?(?![\*\{])[^\s""']{6,}", RegexOptions.Compiled), 7),
    ];

    public IReadOnlyList<string> SupportedDataTypes { get; } =
        Patterns.Select(p => p.DataType).ToList().AsReadOnly();

    public async IAsyncEnumerable<SensitiveDataFinding> ScanAsync(
        string rootPath,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var files = Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories)
            .Where(f => SupportedExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()));

        foreach (var filePath in files)
        {
            ct.ThrowIfCancellationRequested();

            FileInfo fi;
            try
            {
                fi = new FileInfo(filePath);
                if (fi.Length > 10 * 1024 * 1024)
                    continue;
            }
            catch
            {
                continue;
            }

            await foreach (var finding in ScanFileAsync(filePath, ct))
                yield return finding;
        }
    }

    private static async IAsyncEnumerable<SensitiveDataFinding> ScanFileAsync(
        string filePath,
        [EnumeratorCancellation] CancellationToken ct)
    {
        int lineNumber = 0;
        IAsyncEnumerable<string> lines;
        try
        {
            lines = File.ReadLinesAsync(filePath, ct);
        }
        catch
        {
            yield break;
        }

        await foreach (var line in lines.WithCancellation(ct))
        {
            lineNumber++;
            foreach (var (dataType, pattern, severity) in Patterns)
            {
                MatchCollection matches;
                try
                {
                    matches = pattern.Matches(line);
                }
                catch
                {
                    continue;
                }

                foreach (Match match in matches)
                {
                    if (dataType == "CreditCard")
                    {
                        var digits = Regex.Replace(match.Value, @"\D", "");
                        if (!IsValidLuhn(digits))
                            continue;
                    }

                    yield return new SensitiveDataFinding
                    {
                        Id = Guid.NewGuid(),
                        FilePath = filePath,
                        DataType = dataType,
                        MatchSnippet = MaskSensitiveData(dataType, match.Value),
                        LineNumber = lineNumber,
                        Severity = severity,
                        FoundAtUtc = DateTime.UtcNow
                    };
                }
            }
        }
    }

    private static string MaskSensitiveData(string dataType, string value)
    {
        if (dataType == "CreditCard")
        {
            var digits = Regex.Replace(value, @"\D", "");
            if (digits.Length >= 8)
            {
                var first4 = digits[..4];
                var last4 = digits[^4..];
                var masked = new string('*', digits.Length - 8);
                return $"{first4}{masked}{last4}";
            }
        }

        if (value.Length <= 8)
            return new string('*', value.Length);

        var visibleChars = Math.Min(4, value.Length / 4);
        return value[..visibleChars] + new string('*', value.Length - visibleChars * 2) + value[^visibleChars..];
    }

    private static bool IsValidLuhn(string number)
    {
        int sum = 0;
        bool alternate = false;
        for (int i = number.Length - 1; i >= 0; i--)
        {
            if (!char.IsDigit(number[i])) return false;
            int n = number[i] - '0';
            if (alternate) { n *= 2; if (n > 9) n -= 9; }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }
}

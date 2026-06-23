using System.Security.Cryptography;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.SelfIntegrity;

public class SelfIntegrityService : ISelfIntegrityService
{
    private static readonly string BaselineFilePath =
        Path.Combine(AppContext.BaseDirectory, "selfintegrity-baseline.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public async Task<SelfIntegrityReport> VerifyAsync(CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(BaselineFilePath))
            {
                return new SelfIntegrityReport(
                    IsIntact: true,
                    TamperedFiles: Array.Empty<string>(),
                    MissingFiles: Array.Empty<string>(),
                    CheckedAtUtc: DateTime.UtcNow);
            }

            var baselineJson = await File.ReadAllTextAsync(BaselineFilePath, ct);
            var baseline = JsonSerializer.Deserialize<Dictionary<string, string>>(baselineJson);
            if (baseline is null)
            {
                return new SelfIntegrityReport(
                    IsIntact: true,
                    TamperedFiles: Array.Empty<string>(),
                    MissingFiles: Array.Empty<string>(),
                    CheckedAtUtc: DateTime.UtcNow);
            }

            var tampered = new List<string>();
            var missing = new List<string>();

            foreach (var (fileName, expectedHash) in baseline)
            {
                ct.ThrowIfCancellationRequested();
                var fullPath = Path.Combine(AppContext.BaseDirectory, fileName);

                if (!File.Exists(fullPath))
                {
                    missing.Add(fileName);
                    continue;
                }

                var currentHash = await ComputeSha256Async(fullPath, ct);
                if (!string.Equals(currentHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    tampered.Add(fileName);
            }

            return new SelfIntegrityReport(
                IsIntact: tampered.Count == 0 && missing.Count == 0,
                TamperedFiles: tampered.AsReadOnly(),
                MissingFiles: missing.AsReadOnly(),
                CheckedAtUtc: DateTime.UtcNow);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new SelfIntegrityReport(
                IsIntact: true,
                TamperedFiles: Array.Empty<string>(),
                MissingFiles: Array.Empty<string>(),
                CheckedAtUtc: DateTime.UtcNow);
        }
    }

    public async Task<bool> SaveBaselineAsync(CancellationToken ct = default)
    {
        try
        {
            var baseDir = AppContext.BaseDirectory;
            var files = Directory.GetFiles(baseDir, "*.dll")
                .Concat(Directory.GetFiles(baseDir, "*.exe"))
                .ToList();

            var baseline = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var filePath in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(filePath);
                var hash = await ComputeSha256Async(filePath, ct);
                baseline[fileName] = hash;
            }

            var json = JsonSerializer.Serialize(baseline, JsonOptions);
            await File.WriteAllTextAsync(BaselineFilePath, json, ct);

            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string> ComputeSha256Async(string filePath, CancellationToken ct)
    {
        using var sha256 = SHA256.Create();
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, useAsync: true);
        var hashBytes = await sha256.ComputeHashAsync(stream, ct);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}

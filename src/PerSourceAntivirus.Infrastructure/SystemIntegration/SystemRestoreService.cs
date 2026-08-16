using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class SystemRestoreService : ISystemRestoreService
{
    private const int TimeoutMs = 60_000;

    public async Task<bool> CreateRestorePointAsync(string description, CancellationToken ct = default)
    {
        var script = $"Checkpoint-Computer -Description '{description.Replace("'", "''")}' -RestorePointType MODIFY_SETTINGS";
        var (exitCode, _, _) = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        return exitCode == 0;
    }

    public async Task<IReadOnlyList<SystemRestorePointInfo>> GetRestorePointsAsync(CancellationToken ct = default)
    {
        const string script = "Get-ComputerRestorePoint | Select-Object SequenceNumber,Description,CreationTime,RestorePointType | ConvertTo-Json -Compress";
        var (exitCode, stdout, _) = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        if (exitCode != 0 || string.IsNullOrWhiteSpace(stdout)) return [];

        try
        {
            var trimmed = stdout.Trim();
            if (trimmed.Length == 0) return [];

            using var doc = JsonDocument.Parse(trimmed);
            var elements = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().ToList()
                : [doc.RootElement];

            var result = new List<SystemRestorePointInfo>();
            foreach (var el in elements)
            {
                var seq = el.TryGetProperty("SequenceNumber", out var seqEl) ? seqEl.GetInt32() : 0;
                var desc = el.TryGetProperty("Description", out var descEl) ? descEl.GetString() ?? "" : "";
                var type = el.TryGetProperty("RestorePointType", out var typeEl) ? typeEl.ToString() : "";

                DateTime created = DateTime.MinValue;
                if (el.TryGetProperty("CreationTime", out var createdEl))
                {
                    var raw = createdEl.ToString();
                    var digits = new string(raw.Where(char.IsDigit).ToArray());
                    if (digits.Length > 0 && long.TryParse(digits, out var ms))
                        created = DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime;
                }

                result.Add(new SystemRestorePointInfo(seq, desc, created, type));
            }
            return result;
        }
        catch
        {
            return [];
        }
    }

    public async Task<bool> RestoreToPointAsync(int sequenceNumber, CancellationToken ct = default)
    {
        var script = $"Restore-Computer -RestorePoint {sequenceNumber} -Confirm:$false";
        var (exitCode, _, _) = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        return exitCode == 0;
    }

    private static async Task<(int exitCode, string stdout, string stderr)> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        var psi = new ProcessStartInfo("pwsh")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(encodedCommand);

        using var process = System.Diagnostics.Process.Start(psi);
        if (process is null) return (-1, "", "Failed to start pwsh");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeoutMs);
        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return (-1, "", "Timed out");
        }

        return (process.ExitCode, await stdoutTask, await stderrTask);
    }
}

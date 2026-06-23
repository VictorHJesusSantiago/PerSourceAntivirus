using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Sandbox;

[SupportedOSPlatform("windows")]
public sealed class ScriptSandboxService(IScriptSandboxResultRepository repo) : IScriptSandboxService
{
    private static readonly (string Pattern, string Label)[] SuspiciousPatterns =
    [
        ("[System.Reflection", "[System.Reflection"),
        ("GetDelegateForFunctionPointer", "GetDelegateForFunctionPointer"),
        ("VirtualAlloc", "VirtualAlloc"),
        ("WriteProcessMemory", "WriteProcessMemory"),
        ("CreateRemoteThread", "CreateRemoteThread"),
        ("AmsiScanBuffer", "AmsiScanBuffer"),
        ("amsiContext", "amsiContext"),
        ("[Byte[]", "[Byte[]]"),
        ("-EncodedCommand", "-EncodedCommand"),
        ("Invoke-Expression", "Invoke-Expression"),
    ];

    public async Task<ScriptSandboxResult> AnalyzeAsync(string scriptContent, string scriptType, CancellationToken ct = default)
    {
        var scriptBytes = Encoding.UTF8.GetBytes(scriptContent);
        var hashBytes = SHA256.HashData(scriptBytes);
        var scriptHash = Convert.ToHexString(hashBytes).ToLowerInvariant();

        var foundPatterns = new List<string>();
        var lowerContent = scriptContent;

        foreach (var (pattern, label) in SuspiciousPatterns)
        {
            if (lowerContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                foundPatterns.Add(label);
        }

        var score = Math.Min(foundPatterns.Count * 10, 100);

        var verdict = score >= 50 ? "Malicious" : score >= 20 ? "Suspicious" : "Clean";
        var severity = score >= 50 ? 9 : score >= 20 ? 5 : 1;

        var preview = scriptContent.Length <= 200 ? scriptContent : scriptContent[..200];

        bool wasSandboxed = false;
        string sandboxOutput = string.Empty;

        if (score >= 20 && (scriptType.Equals("PowerShell", StringComparison.OrdinalIgnoreCase) ||
                             scriptType.Equals("ps1", StringComparison.OrdinalIgnoreCase)))
        {
            (wasSandboxed, sandboxOutput) = await TrySandboxExecuteAsync(scriptContent, scriptType, ct);
        }

        var behavioralFindings = foundPatterns.Count > 0
            ? string.Join(", ", foundPatterns)
            : "None";

        if (!string.IsNullOrWhiteSpace(sandboxOutput))
            behavioralFindings = behavioralFindings + "; SandboxOutput: " + sandboxOutput[..Math.Min(200, sandboxOutput.Length)];

        var result = new ScriptSandboxResult
        {
            Id = Guid.NewGuid(),
            ScriptType = scriptType,
            ScriptHash = scriptHash,
            ScriptPreview = preview,
            AmsiScore = score,
            WasSandboxed = wasSandboxed,
            BehavioralFindings = behavioralFindings,
            Verdict = verdict,
            Severity = severity,
            AnalyzedAtUtc = DateTime.UtcNow
        };

        await repo.AddAsync(result, ct);
        return result;
    }

    private static async Task<(bool Sandboxed, string Output)> TrySandboxExecuteAsync(
        string scriptContent,
        string scriptType,
        CancellationToken ct)
    {
        var tmpFile = Path.Combine(Path.GetTempPath(), $"psa_sandbox_{Guid.NewGuid():N}.ps1");
        try
        {
            await File.WriteAllTextAsync(tmpFile, scriptContent, Encoding.UTF8, ct);

            var pwshPath = "pwsh.exe";
            if (!File.Exists(pwshPath))
                pwshPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "PowerShell", "7", "pwsh.exe");

            if (!File.Exists(pwshPath))
                pwshPath = "powershell.exe";

            var psi = new System.Diagnostics.ProcessStartInfo(pwshPath,
                $"-NonInteractive -NoProfile -ExecutionPolicy Bypass -File \"{tmpFile}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var process = SysProcess.Start(psi);
            if (process == null) return (false, string.Empty);

            var jobHandle = CreateJobObjectForProcess(process);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));

            var stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
            }
            finally
            {
                jobHandle?.Dispose();
            }

            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            return (true, (stdout + stderr).Trim());
        }
        catch
        {
            return (false, string.Empty);
        }
        finally
        {
            try { File.Delete(tmpFile); } catch { }
        }
    }

    private static SafeFileHandle? CreateJobObjectForProcess(SysProcess process)
    {
        try
        {
            var jobHandle = CreateJobObjectNative(IntPtr.Zero, null);
            if (!jobHandle.IsInvalid)
                AssignProcessToJobObject(jobHandle, process.SafeHandle);
            return jobHandle;
        }
        catch { return null; }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObjectNative(IntPtr lpJobAttributes, string? lpName);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle hJob, System.Runtime.InteropServices.SafeHandle hProcess);
}

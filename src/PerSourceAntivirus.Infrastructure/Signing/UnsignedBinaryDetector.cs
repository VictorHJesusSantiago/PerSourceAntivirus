using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Signing;

// Flags processes whose main executable is unsigned (or signed but untrusted) and running
// from a location commonly abused for dropped/downloaded malware.
[SupportedOSPlatform("windows")]
public sealed class UnsignedBinaryDetector : IUnsignedBinaryDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IAuthenticodeVerifier _verifier;
    private readonly ConcurrentDictionary<int, DateTime> _alerted = new();
    private volatile bool _running;

    private static readonly string[] SuspiciousDirFragments =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Path.GetTempPath()
    };

    public event EventHandler<UnsignedBinaryAlertEventArgs>? AlertDetected;

    public UnsignedBinaryDetector(IServiceScopeFactory scopeFactory, IAuthenticodeVerifier verifier)
    {
        _scopeFactory = scopeFactory;
        _verifier = verifier;
    }

    private async Task PersistAsync(UnsignedBinaryAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IUnsignedBinaryAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                await Diagnostics.DetectorScanScope.RunAsync(_scopeFactory, nameof(UnsignedBinaryDetector), () => ScanOnceAsync(ct));
                await Task.Delay(TimeSpan.FromSeconds(25), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task ScanOnceAsync(CancellationToken ct)
    {
        SysProcess[] processes;
        try { processes = SysProcess.GetProcesses(); }
        catch (Exception) { return; }

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            try { await EvaluateProcessAsync(proc, ct); }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task EvaluateProcessAsync(SysProcess proc, CancellationToken ct)
    {
        int pid;
        string procName;
        string? filePath;
        try
        {
            pid = proc.Id;
            procName = proc.ProcessName;
            filePath = proc.MainModule?.FileName;
        }
        catch (Exception) { return; }

        if (pid <= 4 || string.IsNullOrEmpty(filePath)) return;
        if (!IsSuspiciousLocation(filePath)) return;

        var now = DateTime.UtcNow;
        if (_alerted.TryGetValue(pid, out var last) && (now - last).TotalHours < 1) return;

        var verification = await _verifier.VerifyAsync(filePath, ct).ConfigureAwait(false);
        if (verification.IsSigned && verification.IsTrusted) return;

        _alerted[pid] = now;
        var reason = verification.IsSigned ? "SignedButUntrusted" : "UnsignedInSuspiciousLocation";
        var severity = verification.IsSigned ? 5 : 7;

        var alert = new UnsignedBinaryAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            FilePath = filePath,
            IsSigned = verification.IsSigned,
            IsTrusted = verification.IsTrusted,
            Reason = reason,
            Severity = severity,
            DetectedAtUtc = now
        };

        await PersistAsync(alert, ct).ConfigureAwait(false);
        AlertDetected?.Invoke(this, new UnsignedBinaryAlertEventArgs(alert));
    }

    private static bool IsSuspiciousLocation(string filePath)
    {
        foreach (var fragment in SuspiciousDirFragments)
        {
            if (fragment.Length > 0 && filePath.StartsWith(fragment, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}

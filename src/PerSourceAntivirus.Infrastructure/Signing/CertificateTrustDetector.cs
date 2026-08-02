using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Signing;

// Watches running processes and flags any whose signing certificate thumbprint is on the
// administrator-maintained blacklist (e.g. a leaked/abused code-signing cert).
[SupportedOSPlatform("windows")]
public sealed class CertificateTrustDetector : ICertificateTrustDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IAuthenticodeVerifier _verifier;
    private readonly ICertificateTrustListService _trustList;
    private readonly ConcurrentDictionary<int, DateTime> _alerted = new();
    private volatile bool _running;

    public event EventHandler<CertificateTrustAlertEventArgs>? AlertDetected;

    public CertificateTrustDetector(
        IServiceScopeFactory scopeFactory,
        IAuthenticodeVerifier verifier,
        ICertificateTrustListService trustList)
    {
        _scopeFactory = scopeFactory;
        _verifier = verifier;
        _trustList = trustList;
    }

    private async Task PersistAsync(CertificateTrustAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<ICertificateTrustAlertRepository>();
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
                try { await ScanOnceAsync(ct); }
                catch (Exception) { }
                await Task.Delay(TimeSpan.FromSeconds(45), ct);
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

        var now = DateTime.UtcNow;
        if (_alerted.TryGetValue(pid, out var last) && (now - last).TotalHours < 1) return;

        var verification = await _verifier.VerifyAsync(filePath, ct).ConfigureAwait(false);
        if (!verification.IsSigned || verification.Thumbprint is null) return;

        var entry = await _trustList.FindByThumbprintAsync(verification.Thumbprint, ct).ConfigureAwait(false);
        if (entry is null || !entry.TrustLevel.Equals("Blacklisted", StringComparison.OrdinalIgnoreCase)) return;

        _alerted[pid] = now;

        var alert = new CertificateTrustAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            FilePath = filePath,
            Thumbprint = verification.Thumbprint,
            SubjectName = verification.SignerSubject ?? string.Empty,
            Reason = "BlacklistedCertificate",
            Severity = 9,
            DetectedAtUtc = now
        };

        await PersistAsync(alert, ct).ConfigureAwait(false);
        AlertDetected?.Invoke(this, new CertificateTrustAlertEventArgs(alert));
    }
}

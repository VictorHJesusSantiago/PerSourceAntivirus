using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;
using System.Management;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class ProcessGhostingDetector : IProcessGhostingDetector, IDisposable
{
    private readonly Microsoft.Extensions.DependencyInjection.IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<int, DateTime> _checkedPids = new();
    private volatile bool _running;
    private ManagementEventWatcher? _watcher;
    private bool _disposed;

    private static readonly string TempPath =
        System.IO.Path.GetTempPath().TrimEnd(System.IO.Path.DirectorySeparatorChar,
            System.IO.Path.AltDirectorySeparatorChar);

    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            .TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);

    public event EventHandler<ProcessGhostingAlertEventArgs>? AlertDetected;

    public ProcessGhostingDetector(Microsoft.Extensions.DependencyInjection.IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(ProcessGhostingAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IProcessGhostingAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;

        try
        {
            _watcher = new ManagementEventWatcher(
                new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"));

            _watcher.EventArrived += OnProcessCreated;
            _watcher.Start();
        }
        catch (Exception) { }

        ct.Register(() =>
        {
            _running = false;
            try { _watcher?.Stop(); } catch { }
        });

        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try { await PeriodicScanAsync(ct); }
                catch (Exception) { }
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring()
    {
        _running = false;
        try { _watcher?.Stop(); } catch { }
    }

    private void OnProcessCreated(object sender, EventArrivedEventArgs e)
    {
        if (!_running) return;
        try
        {
            var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var pid = Convert.ToInt32(targetInstance["ProcessId"]);
            var execPath = targetInstance["ExecutablePath"] as string ?? string.Empty;
            _ = Task.Run(() => CheckProcessAsync(pid, execPath, CancellationToken.None));
        }
        catch { }
    }

    private async Task PeriodicScanAsync(CancellationToken ct)
    {
        SysProcess[] processes;
        try { processes = SysProcess.GetProcesses(); }
        catch (Exception) { return; }

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                int pid;
                string imagePath;
                try
                {
                    pid = proc.Id;
                    imagePath = proc.MainModule?.FileName ?? string.Empty;
                }
                catch (Exception) { continue; }

                if (pid <= 4) continue;

                var now = DateTime.UtcNow;
                if (_checkedPids.TryGetValue(pid, out var last) && (now - last).TotalMinutes < 5)
                    continue;

                await CheckProcessAsync(pid, imagePath, ct);
            }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task CheckProcessAsync(int pid, string imagePath, CancellationToken ct)
    {
        if (pid <= 4) return;

        if (string.IsNullOrEmpty(imagePath))
        {
            try
            {
                var liveProc = SysProcess.GetProcessById(pid);
                imagePath = liveProc.MainModule?.FileName ?? string.Empty;
            }
            catch (Exception) { }
        }

        if (string.IsNullOrEmpty(imagePath)) return;

        _checkedPids[pid] = DateTime.UtcNow;

        string processName;
        try
        {
            var p = SysProcess.GetProcessById(pid);
            processName = p.ProcessName;
        }
        catch { processName = System.IO.Path.GetFileNameWithoutExtension(imagePath); }

        bool fileExists = System.IO.File.Exists(imagePath);
        if (!fileExists)
        {
            await FireAlertAsync(new ProcessGhostingAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = processName,
                ProcessId = pid,
                ReportedImagePath = imagePath,
                ImageFileExistsOnDisk = false,
                ImageFileAccessible = false,
                DetectionMethod = "FileNotFoundOnDisk",
                Severity = 10,
                DetectedAtUtc = DateTime.UtcNow
            }, ct);
            return;
        }

        bool inTempDir = IsInTempDirectory(imagePath);
        if (inTempDir)
        {
            var ext = System.IO.Path.GetExtension(imagePath);
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            {
                bool accessible = false;
                try
                {
                    using var fs = new System.IO.FileStream(imagePath, System.IO.FileMode.Open,
                        System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite);
                    accessible = true;
                }
                catch (Exception) { }

                await FireAlertAsync(new ProcessGhostingAlert
                {
                    Id = Guid.NewGuid(),
                    ProcessName = processName,
                    ProcessId = pid,
                    ReportedImagePath = imagePath,
                    ImageFileExistsOnDisk = true,
                    ImageFileAccessible = accessible,
                    DetectionMethod = "TempDirImage",
                    Severity = 7,
                    DetectedAtUtc = DateTime.UtcNow
                }, ct);
                return;
            }
        }

        try
        {
            using var fs = new System.IO.FileStream(imagePath, System.IO.FileMode.Open,
                System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite);
        }
        catch (System.IO.IOException ioEx)
        {
            string msg = ioEx.Message;
            if (msg.Contains("used by another process", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("access denied", StringComparison.OrdinalIgnoreCase))
            {
                await FireAlertAsync(new ProcessGhostingAlert
                {
                    Id = Guid.NewGuid(),
                    ProcessName = processName,
                    ProcessId = pid,
                    ReportedImagePath = imagePath,
                    ImageFileExistsOnDisk = true,
                    ImageFileAccessible = false,
                    DetectionMethod = "FilePendingDelete",
                    Severity = 8,
                    DetectedAtUtc = DateTime.UtcNow
                }, ct);
            }
        }
        catch (Exception) { }
    }

    private async Task FireAlertAsync(ProcessGhostingAlert alert, CancellationToken ct)
    {
        await PersistAsync(alert, ct).ConfigureAwait(false);
        AlertDetected?.Invoke(this, new ProcessGhostingAlertEventArgs(alert));
    }

    private static bool IsInTempDirectory(string path)
    {
        return path.StartsWith(TempPath, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(LocalAppData, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _running = false;
        try { _watcher?.Stop(); } catch { }
        _watcher?.Dispose();
    }
}

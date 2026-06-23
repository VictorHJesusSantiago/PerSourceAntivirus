using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IProcessDoppelgangingDetector, ProcessDoppelgangingDetector>();
[SupportedOSPlatform("windows")]
public sealed class ProcessDoppelgangingDetector : IProcessDoppelgangingDetector, IDisposable
{
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int ProcessImageFileName = 27;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, out uint returnLength);

    public event EventHandler<ProcessDoppelgangingAlertEventArgs>? AlertDetected;

    private volatile bool _running;
    private ManagementEventWatcher? _watcher;
    private bool _disposed;

    public Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;

        ct.Register(() =>
        {
            _running = false;
            try { _watcher?.Stop(); } catch { }
        });

        _watcher = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"));

        _watcher.EventArrived += (_, e) =>
        {
            if (!_running) return;
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var execPath = (string?)targetInstance["ExecutablePath"];
                if (string.IsNullOrEmpty(execPath)) return;

                var procName = (string)(targetInstance["Name"] ?? "");
                var pid = Convert.ToInt32(targetInstance["ProcessId"]);

                _ = Task.Run(() => AnalyzeProcessAsync(pid, procName, execPath));
            }
            catch { /* don't crash the watcher */ }
        };

        _watcher.Start();
        return Task.CompletedTask;
    }

    public void StopMonitoring()
    {
        _running = false;
        try { _watcher?.Stop(); } catch { }
    }

    private async Task AnalyzeProcessAsync(int pid, string procName, string execPath)
    {
        await Task.Yield();

        bool exists = File.Exists(execPath);
        string reason;
        int severity;

        if (!exists)
        {
            reason = "ImageFileNotFound";
            severity = 9;
        }
        else if (execPath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) ||
                 execPath.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase) ||
                 execPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase))
        {
            reason = "TempPathImage";
            severity = 7;
        }
        else
        {
            reason = string.Empty;
            severity = 0;

            var handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (handle != IntPtr.Zero)
            {
                IntPtr buf = IntPtr.Zero;
                try
                {
                    buf = Marshal.AllocHGlobal(1024);
                    int ntStatus = NtQueryInformationProcess(handle, ProcessImageFileName, buf, 1024, out _);
                    if (ntStatus == 0)
                    {
                        short len = Marshal.ReadInt16(buf, 0);
                        if (len > 0)
                        {
                            IntPtr strPtr = Marshal.ReadIntPtr(buf, 4);
                            string ntPath = Marshal.PtrToStringUni(strPtr, len / 2) ?? string.Empty;
                            if (ntPath.Length > 0)
                            {
                                // NT device path won't match a Win32 path directly
                                reason = "PathMismatch";
                                severity = 5;
                            }
                        }
                    }
                }
                catch { /* best-effort */ }
                finally
                {
                    if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                    CloseHandle(handle);
                }
            }
        }

        if (!string.IsNullOrEmpty(reason))
        {
            var alert = new ProcessDoppelgangingAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = procName,
                ProcessId = pid,
                ReportedImagePath = execPath,
                ImageExistsOnDisk = exists,
                SuspicionReason = reason,
                Severity = severity,
                DetectedAtUtc = DateTime.UtcNow
            };

            AlertDetected?.Invoke(this, new ProcessDoppelgangingAlertEventArgs(alert));
        }
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

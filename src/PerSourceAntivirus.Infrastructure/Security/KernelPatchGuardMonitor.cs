using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class KernelPatchGuardMonitor(IKernelPatchGuardAlertRepository repo) : IKernelPatchGuardMonitor
{
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;

    public event EventHandler<KernelPatchGuardAlertEventArgs>? AlertDetected;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool pbDebuggerPresent);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _monitorTask = RunMonitorLoopAsync(_cts.Token);
        await Task.CompletedTask;
    }

    public void StopMonitoring()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private async Task RunMonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var alerts = await CheckAsync(ct);
                foreach (var alert in alerts)
                {
                    await repo.AddAsync(alert, ct);
                    AlertDetected?.Invoke(this, new KernelPatchGuardAlertEventArgs(alert));
                }
            }
            catch (OperationCanceledException) { break; }
            catch { }

            try { await Task.Delay(TimeSpan.FromSeconds(60), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task<IReadOnlyList<KernelPatchGuardAlert>> CheckAsync(CancellationToken ct)
    {
        return await Task.Run<IReadOnlyList<KernelPatchGuardAlert>>(() =>
        {
            var alerts = new List<KernelPatchGuardAlert>();
            var now = DateTime.UtcNow;

            CheckTestSigningMode(alerts, now);
            CheckKernelDebugging(alerts, now);
            CheckCiConfig(alerts, now);
            CheckKernelDebuggerPresent(alerts, now);

            return alerts;
        }, ct);
    }

    private static void CheckTestSigningMode(List<KernelPatchGuardAlert> alerts, DateTime now)
    {
        try
        {
            using var ps = SysProcess.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "bcdedit.exe",
                Arguments = "/enum {current}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            });
            if (ps == null) return;
            var output = ps.StandardOutput.ReadToEnd();
            ps.WaitForExit(5000);

            if (output.Contains("testsigning", StringComparison.OrdinalIgnoreCase)
                && output.Contains("yes", StringComparison.OrdinalIgnoreCase))
            {
                alerts.Add(new KernelPatchGuardAlert
                {
                    Id = Guid.NewGuid(),
                    BypassMethodType = "TestSigningMode",
                    Details = "Windows is running in test signing mode — driver signature enforcement is disabled",
                    TargetFunction = "nt!PsLoadImageNotifyRoutine",
                    Severity = 8,
                    DetectedAtUtc = now
                });
            }
        }
        catch { }
    }

    private static void CheckKernelDebugging(List<KernelPatchGuardAlert> alerts, DateTime now)
    {
        try
        {
            using var crashKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CrashControl");
            if (crashKey == null) return;

            var enableUserDump = crashKey.GetValue("EnableUserDump");
            if (enableUserDump != null && Convert.ToInt32(enableUserDump) != 0)
            {
                alerts.Add(new KernelPatchGuardAlert
                {
                    Id = Guid.NewGuid(),
                    BypassMethodType = "KernelDebugMode",
                    Details = "EnableUserDump is set — system may be in kernel debug mode",
                    TargetFunction = "nt!KdDebuggerEnabled",
                    Severity = 6,
                    DetectedAtUtc = now
                });
            }
        }
        catch { }
    }

    private static void CheckCiConfig(List<KernelPatchGuardAlert> alerts, DateTime now)
    {
        try
        {
            using var ciKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Config");
            if (ciKey == null) return;

            var skipInvalidSig = ciKey.GetValue("SkipInvalidSignatures");
            if (skipInvalidSig != null && Convert.ToInt32(skipInvalidSig) != 0)
            {
                alerts.Add(new KernelPatchGuardAlert
                {
                    Id = Guid.NewGuid(),
                    BypassMethodType = "CiBypass",
                    Details = "CI SkipInvalidSignatures is set — code integrity checking may be bypassed",
                    TargetFunction = "ci.dll!CiInitialize",
                    Severity = 9,
                    DetectedAtUtc = now
                });
            }

            using var protectedKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Protected");
            if (protectedKey != null)
            {
                var licensed = protectedKey.GetValue("Licensed");
                if (licensed != null && Convert.ToInt32(licensed) == 0)
                {
                    alerts.Add(new KernelPatchGuardAlert
                    {
                        Id = Guid.NewGuid(),
                        BypassMethodType = "CiBypass",
                        Details = "CI Protected\\Licensed is 0 — possible KPP/DSE bypass",
                        TargetFunction = "ci.dll!CiValidateImageData",
                        Severity = 9,
                        DetectedAtUtc = now
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckKernelDebuggerPresent(List<KernelPatchGuardAlert> alerts, DateTime now)
    {
        try
        {
            if (IsDebuggerPresent())
            {
                alerts.Add(new KernelPatchGuardAlert
                {
                    Id = Guid.NewGuid(),
                    BypassMethodType = "DebuggerAttached",
                    Details = "User-mode debugger is present — potential bypass tool attached",
                    TargetFunction = "kernel32.dll!IsDebuggerPresent",
                    Severity = 7,
                    DetectedAtUtc = now
                });
            }

            var hProc = GetCurrentProcess();
            if (CheckRemoteDebuggerPresent(hProc, out var remoteDebugger) && remoteDebugger)
            {
                alerts.Add(new KernelPatchGuardAlert
                {
                    Id = Guid.NewGuid(),
                    BypassMethodType = "RemoteDebuggerAttached",
                    Details = "Remote debugger is attached to the current process",
                    TargetFunction = "kernel32.dll!CheckRemoteDebuggerPresent",
                    Severity = 7,
                    DetectedAtUtc = now
                });
            }
        }
        catch { }
    }
}

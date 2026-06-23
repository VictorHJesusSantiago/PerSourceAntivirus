using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class ProcessMitigationService : IProcessMitigationService
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(int policy, IntPtr lpBuffer, int dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    {
        public uint Flags;
    }

    private const int ProcessDynamicCodePolicy = 2;
    private const int ProcessSignaturePolicy = 8;
    private const int ProcessControlFlowGuardPolicy = 9;

    private readonly List<CfgViolationAlert> _cfgViolations = [];
    private readonly Lock _lock = new();

    public bool ApplyAcgToCurrentProcess()
    {
        var policy = new PROCESS_MITIGATION_DYNAMIC_CODE_POLICY { Flags = 1 };
        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(policy));
        try
        {
            Marshal.StructureToPtr(policy, ptr, false);
            return SetProcessMitigationPolicy(ProcessDynamicCodePolicy, ptr, Marshal.SizeOf(policy));
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public bool ApplyCigToCurrentProcess()
    {
        var policy = new PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY { Flags = 1 };
        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(policy));
        try
        {
            Marshal.StructureToPtr(policy, ptr, false);
            return SetProcessMitigationPolicy(ProcessSignaturePolicy, ptr, Marshal.SizeOf(policy));
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public bool ApplyCfgToCurrentProcess()
    {
        var policy = new PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags = 1 };
        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(policy));
        try
        {
            Marshal.StructureToPtr(policy, ptr, false);
            return SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, ptr, Marshal.SizeOf(policy));
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public async Task<IReadOnlyList<CfgViolationAlert>> MonitorCfgViolationsAsync(int pollIntervalSeconds, CancellationToken ct)
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        var results = new List<CfgViolationAlert>();
        var seen = new HashSet<string>();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(pollIntervalSeconds), ct).ConfigureAwait(false);

                var alerts = PollEventLog();
                foreach (var alert in alerts)
                {
                    var key = $"{alert.ProcessId}:{alert.ViolationAddress}:{alert.ExceptionCode}";
                    if (seen.Add(key))
                        results.Add(alert);
                }

                lock (_lock)
                {
                    foreach (var alert in _cfgViolations)
                    {
                        var key = $"{alert.ProcessId}:{alert.ViolationAddress}:{alert.ExceptionCode}";
                        if (seen.Add(key))
                            results.Add(alert);
                    }
                    _cfgViolations.Clear();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
        }

        return results.AsReadOnly();
    }

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            var hResult = (uint)ex.HResult;
            if (hResult == 0xC0000409 || ex.Message.Contains("STATUS_STACK_BUFFER_OVERRUN", StringComparison.OrdinalIgnoreCase))
            {
                var alert = new CfgViolationAlert
                {
                    Id = Guid.NewGuid(),
                    ProcessName = SysProcess.GetCurrentProcess().ProcessName,
                    ProcessId = Environment.ProcessId,
                    ViolationAddress = "0x0",
                    ExceptionCode = $"0x{hResult:X8}",
                    Details = ex.Message,
                    Severity = 9,
                    DetectedAtUtc = DateTime.UtcNow
                };
                lock (_lock)
                {
                    _cfgViolations.Add(alert);
                }
            }
        }
    }

    private static List<CfgViolationAlert> PollEventLog()
    {
        var results = new List<CfgViolationAlert>();
        try
        {
            const string logName = "Microsoft-Windows-Security-Mitigations/UserMode";

            var allLogNames = System.Diagnostics.Eventing.Reader.EventLogSession.GlobalSession.GetLogNames();
            if (!allLogNames.Contains(logName))
                return results;

            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                logName,
                System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[EventID=10]]");

            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
            var cutoff = DateTime.UtcNow.AddMinutes(-5);

            System.Diagnostics.Eventing.Reader.EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    if (record.TimeCreated?.ToUniversalTime() < cutoff)
                        continue;

                    var processId = 0;
                    var processName = string.Empty;

                    if (record.ProcessId.HasValue)
                        processId = (int)record.ProcessId.Value;

                    try
                    {
                        using var proc = SysProcess.GetProcessById(processId);
                        processName = proc.ProcessName;
                    }
                    catch
                    {
                        processName = "unknown";
                    }

                    var description = string.Empty;
                    try { description = record.FormatDescription() ?? string.Empty; }
                    catch { }

                    results.Add(new CfgViolationAlert
                    {
                        Id = Guid.NewGuid(),
                        ProcessName = processName,
                        ProcessId = processId,
                        ViolationAddress = "0x0",
                        ExceptionCode = "0xC0000409",
                        Details = description,
                        Severity = 9,
                        DetectedAtUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow
                    });
                }
            }
        }
        catch
        {
        }
        return results;
    }
}

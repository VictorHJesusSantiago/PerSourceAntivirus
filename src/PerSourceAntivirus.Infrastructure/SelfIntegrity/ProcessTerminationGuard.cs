using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SelfIntegrity;

[SupportedOSPlatform("windows")]
public sealed class ProcessTerminationGuard : IDisposable
{
    private static readonly HashSet<string> SuspiciousProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "taskkill.exe", "taskmgr.exe", "procexp.exe", "procexp64.exe",
        "ProcessHacker.exe", "ProcessHacker2.exe", "pskill.exe"
    };

    // SetProcessMitigationPolicy policy IDs (winnt.h)
    private const int ProcessDEPPolicy = 0;
    private const int ProcessStrictHandleCheckPolicy = 3;
    private const int ProcessSignaturePolicy = 8;
    private const int ProcessImageLoadPolicy = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMitigationStrictHandleCheckPolicy
    {
        // Flags: RaiseExceptionOnInvalidHandleReference (bit 0) | HandleExceptionsPermanentlyEnabled (bit 1)
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMitigationBinarySignaturePolicy
    {
        // MicrosoftSignedOnly (bit 0) | StoreSignedOnly (bit 1) | MitigationOptIn (bit 2) | AuditMicrosoftSignedOnly (bit 3) | AuditStoreSignedOnly (bit 4)
        public uint Flags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(
        int MitigationPolicy,
        ref ProcessMitigationStrictHandleCheckPolicy lpBuffer,
        nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(
        int MitigationPolicy,
        ref ProcessMitigationBinarySignaturePolicy lpBuffer,
        nuint dwLength);

    private readonly int _ownPid;
    private readonly string _ownProcessName;
    private readonly Channel<string> _alertChannel;
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;
    private bool _disposed;

    public event EventHandler<string>? AlertRaised;

    public ProcessTerminationGuard()
    {
        _ownPid = Environment.ProcessId;
        _ownProcessName = SysProcess.GetCurrentProcess().ProcessName + ".exe";
        _alertChannel = Channel.CreateUnbounded<string>();
    }

    public void Start()
    {
        if (_disposed) return;

        ApplyProcessMitigations();
        StartProcessStopWatcher();
        StartSuspiciousProcessWatcher();
    }

    // Applies usermode process mitigations that raise the cost of process injection/hijacking.
    // These are not PPL — they cannot fully prevent termination by an admin-level attacker —
    // but they close several low-effort attack vectors.
    private static void ApplyProcessMitigations()
    {
        try
        {
            // Raise exceptions instead of silently failing when a bad/invalid handle is used.
            // Prevents attackers from silently duplicating or manipulating handles.
            var strictHandlePolicy = new ProcessMitigationStrictHandleCheckPolicy
            {
                Flags = 0b11 // RaiseExceptionOnInvalidHandleReference | HandleExceptionsPermanentlyEnabled
            };
            SetProcessMitigationPolicy(
                ProcessStrictHandleCheckPolicy,
                ref strictHandlePolicy,
                (nuint)Marshal.SizeOf<ProcessMitigationStrictHandleCheckPolicy>());
        }
        catch { }

        try
        {
            // Require that all images loaded into this process are signed (audit mode only —
            // MitigationOptIn bit 2 set, enforcement bits 0/1 clear). Logs unsigned DLL loads
            // without blocking legitimate unsigned code the host process may already depend on.
            var signaturePolicy = new ProcessMitigationBinarySignaturePolicy
            {
                Flags = 0b00100 // MitigationOptIn only (audit, not enforcement)
            };
            SetProcessMitigationPolicy(
                ProcessSignaturePolicy,
                ref signaturePolicy,
                (nuint)Marshal.SizeOf<ProcessMitigationBinarySignaturePolicy>());
        }
        catch { }
    }

    private void StartProcessStopWatcher()
    {
        try
        {
            _stopWatcher = new ManagementEventWatcher(
                @"\\.\root\CIMV2",
                $"SELECT * FROM Win32_ProcessStopTrace WHERE ProcessName = '{_ownProcessName}'");

            _stopWatcher.EventArrived += (_, e) =>
            {
                try
                {
                    var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
                    if (pid == _ownPid)
                    {
                        var alert = $"[ProcessTerminationGuard] Own process termination event detected for PID {_ownPid} ({_ownProcessName}) at {DateTime.UtcNow:O}";
                        _alertChannel.Writer.TryWrite(alert);
                        AlertRaised?.Invoke(this, alert);
                    }
                }
                catch { }
            };

            _stopWatcher.Start();
        }
        catch { }
    }

    private void StartSuspiciousProcessWatcher()
    {
        try
        {
            _startWatcher = new ManagementEventWatcher(
                @"\\.\root\CIMV2",
                "SELECT * FROM Win32_ProcessStartTrace");

            _startWatcher.EventArrived += (_, e) =>
            {
                try
                {
                    var processName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? string.Empty;

                    if (SuspiciousProcessNames.Contains(processName))
                    {
                        var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
                        var alert = $"[ProcessTerminationGuard] Suspicious process started: '{processName}' (PID {pid}) that may target our process (PID {_ownPid}) at {DateTime.UtcNow:O}";
                        _alertChannel.Writer.TryWrite(alert);
                        AlertRaised?.Invoke(this, alert);
                    }
                }
                catch { }
            };

            _startWatcher.Start();
        }
        catch { }
    }

    public async IAsyncEnumerable<string> ReadAlertsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        ct.Register(() => _alertChannel.Writer.TryComplete());

        await foreach (var alert in _alertChannel.Reader.ReadAllAsync(ct))
        {
            yield return alert;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { _stopWatcher?.Stop(); } catch { }
        _stopWatcher?.Dispose();

        try { _startWatcher?.Stop(); } catch { }
        _startWatcher?.Dispose();

        _alertChannel.Writer.TryComplete();
    }
}

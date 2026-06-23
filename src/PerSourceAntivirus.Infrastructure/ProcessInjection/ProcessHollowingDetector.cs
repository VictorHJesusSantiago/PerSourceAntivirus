using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IProcessHollowingDetector, ProcessHollowingDetector>();
[SupportedOSPlatform("windows")]
public sealed class ProcessHollowingDetector : IProcessHollowingDetector, IDisposable
{
    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, System.Text.StringBuilder lpFilename, uint nSize);

    public event EventHandler<ProcessHollowingAlertEventArgs>? AlertDetected;

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
                var procName = (string)(targetInstance["Name"] ?? "");
                var pid = Convert.ToInt32(targetInstance["ProcessId"]);
                var parentPid = Convert.ToInt32(targetInstance["ParentProcessId"]);

                string parentName;
                try { parentName = SysProcess.GetProcessById(parentPid).ProcessName; }
                catch { parentName = "unknown"; }

                _ = Task.Run(() => ScanProcessAsync(pid, procName, parentPid, parentName));
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

    private async Task ScanProcessAsync(int pid, string procName, int parentPid, string parentName)
    {
        await Task.Yield();

        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return;

        try
        {
            var steps = new List<string>();
            int severity = 0;
            bool hasPeHeader = false;

            var address = IntPtr.Zero;

            while (true)
            {
                if (!VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
                    break;

                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
                {
                    if (!steps.Contains("RWX_PrivateRegion"))
                        steps.Add("RWX_PrivateRegion");

                    if (regionSize > 65536 && !steps.Contains("LargeRegion"))
                        steps.Add("LargeRegion");

                    var headerBuf = new byte[2];
                    if (ReadProcessMemory(handle, mbi.BaseAddress, headerBuf, 2, out var bytesRead) &&
                        bytesRead >= 2 && headerBuf[0] == 0x4D && headerBuf[1] == 0x5A)
                    {
                        if (!steps.Contains("PeHeader"))
                        {
                            steps.Add("PeHeader");
                            hasPeHeader = true;
                            severity += 4;
                        }
                    }
                }

                var next = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize);
                if (next.ToInt64() <= address.ToInt64()) break;
                address = next;
            }

            if (steps.Count > 0)
            {
                severity = Math.Min(10, steps.Count * 2 + (hasPeHeader ? 4 : 0));

                var alert = new ProcessHollowingAlert
                {
                    Id = Guid.NewGuid(),
                    TargetProcessName = procName,
                    TargetProcessId = pid,
                    InjectorProcessName = parentName,
                    InjectorProcessId = parentPid,
                    DetectedSequence = string.Join(",", steps),
                    StepsDetected = steps.Count,
                    Severity = severity,
                    DetectedAtUtc = DateTime.UtcNow
                };

                AlertDetected?.Invoke(this, new ProcessHollowingAlertEventArgs(alert));
            }
        }
        catch { /* best-effort */ }
        finally
        {
            CloseHandle(handle);
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

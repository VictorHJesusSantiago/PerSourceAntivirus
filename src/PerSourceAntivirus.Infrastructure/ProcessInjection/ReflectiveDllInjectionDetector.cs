using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IReflectiveDllInjectionDetector, ReflectiveDllInjectionDetector>();
[SupportedOSPlatform("windows")]
public sealed class ReflectiveDllInjectionDetector : IReflectiveDllInjectionDetector
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

    public event EventHandler<ReflectiveDllInjectionAlertEventArgs>? AlertDetected;

    private volatile bool _running;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try { await ScanOnceAsync(ct); }
                catch (Exception) { /* don't crash the loop */ }
                await Task.Delay(TimeSpan.FromSeconds(15), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task ScanOnceAsync(CancellationToken ct)
    {
        var processes = SysProcess.GetProcesses();
        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            if (proc.Id <= 4) continue;

            try
            {
                await ScanProcessAsync(proc.Id, proc.ProcessName, ct);
            }
            catch { /* process may have exited */ }
            finally
            {
                proc.Dispose();
            }
        }
    }

    private Task ScanProcessAsync(int pid, string procName, CancellationToken ct)
    {
        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return Task.CompletedTask;

        try
        {
            // Enumerate module base addresses
            var moduleBaseAddresses = new HashSet<long>();
            EnumProcessModules(handle, new IntPtr[256], 256 * 8, out uint needed);
            if (needed > 0)
            {
                var mods = new IntPtr[needed / (uint)IntPtr.Size];
                if (EnumProcessModules(handle, mods, needed, out _))
                {
                    foreach (var mod in mods)
                        moduleBaseAddresses.Add(mod.ToInt64());
                }
            }

            var address = IntPtr.Zero;
            while (!ct.IsCancellationRequested)
            {
                if (!VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
                    break;

                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                var next = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize);

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && (mbi.Protect & 0xF0) != 0)
                {
                    if (!moduleBaseAddresses.Contains(mbi.BaseAddress.ToInt64()))
                    {
                        int readSize = (int)Math.Min(4096, regionSize);
                        var buf = new byte[readSize];
                        if (ReadProcessMemory(handle, mbi.BaseAddress, buf, readSize, out int bytesRead) && bytesRead > 0)
                        {
                            var bytes = bytesRead < buf.Length ? buf[..bytesRead] : buf;
                            bool hasMz = bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A;
                            double entropy = CalculateEntropy(bytes);

                            if (hasMz || (entropy > 6.5 && regionSize > 65536))
                            {
                                string key = $"{pid}_{mbi.BaseAddress.ToInt64()}";
                                if (!_recentAlerts.TryGetValue(key, out var lastAlerted) ||
                                    (DateTime.UtcNow - lastAlerted).TotalMinutes >= 5)
                                {
                                    _recentAlerts[key] = DateTime.UtcNow;

                                    var alert = new ReflectiveDllInjectionAlert
                                    {
                                        Id = Guid.NewGuid(),
                                        TargetProcessName = procName,
                                        TargetProcessId = pid,
                                        SuspiciousBaseAddress = (ulong)mbi.BaseAddress.ToInt64(),
                                        RegionSize = regionSize,
                                        MemoryProtection = mbi.Protect,
                                        HasPeHeader = hasMz,
                                        RegionEntropy = entropy,
                                        Severity = hasMz ? 9 : 7,
                                        DetectedAtUtc = DateTime.UtcNow
                                    };

                                    AlertDetected?.Invoke(this, new ReflectiveDllInjectionAlertEventArgs(alert));
                                }
                            }
                        }
                    }
                }

                if (next.ToInt64() <= address.ToInt64()) break;
                address = next;
            }
        }
        finally
        {
            CloseHandle(handle);
        }

        return Task.CompletedTask;
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var freq = new int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}

using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IModuleStompingDetector, ModuleStompingDetector>();
[SupportedOSPlatform("windows")]
public sealed class ModuleStompingDetector : IModuleStompingDetector
{
    private readonly IModuleStompingAlertRepository _repository;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private readonly ConcurrentDictionary<string, string> _diskHashes = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _running;

    private static readonly HashSet<string> TargetDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll"
    };

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;

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
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

    public event EventHandler<ModuleStompingAlertEventArgs>? AlertDetected;

    public ModuleStompingDetector(IModuleStompingAlertRepository repository)
    {
        _repository = repository;
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
                await Task.Delay(TimeSpan.FromSeconds(60), ct);
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
            try { await ScanProcessAsync(proc, ct); }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task ScanProcessAsync(SysProcess proc, CancellationToken ct)
    {
        int pid;
        string procName;
        try
        {
            pid = proc.Id;
            procName = proc.ProcessName;
        }
        catch (Exception) { return; }

        if (pid <= 4) return;

        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return;

        try
        {
            var moduleHandles = new IntPtr[1024];
            if (!EnumProcessModules(handle, moduleHandles, (uint)(moduleHandles.Length * IntPtr.Size), out uint needed))
                return;

            int moduleCount = (int)(needed / (uint)IntPtr.Size);
            var sb = new StringBuilder(1024);

            for (int m = 0; m < moduleCount; m++)
            {
                if (ct.IsCancellationRequested) break;
                if (moduleHandles[m] == IntPtr.Zero) continue;

                sb.Clear();
                if (GetModuleFileNameEx(handle, moduleHandles[m], sb, (uint)sb.Capacity) == 0)
                    continue;

                string modulePath = sb.ToString();
                string moduleName = System.IO.Path.GetFileName(modulePath);

                if (!TargetDlls.Contains(moduleName)) continue;

                try
                {
                    await CheckModuleAsync(handle, pid, procName, moduleHandles[m], modulePath, moduleName, ct);
                }
                catch (Exception) { }
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private async Task CheckModuleAsync(IntPtr processHandle, int pid, string procName,
        IntPtr moduleBase, string modulePath, string moduleName, CancellationToken ct)
    {
        // Read the PE header from memory (first 4096 bytes)
        var headerBuf = new byte[4096];
        if (!ReadProcessMemory(processHandle, moduleBase, headerBuf, headerBuf.Length, out int headerRead)
            || headerRead < 0x40)
            return;

        // Parse PE header to find .text section
        int lfanew;
        try { lfanew = BitConverter.ToInt32(headerBuf, 0x3C); }
        catch (Exception) { return; }

        if (lfanew <= 0 || lfanew + 24 + 2 >= headerRead) return;

        int numSections;
        int sizeOfOptHeader;
        try
        {
            numSections = BitConverter.ToInt16(headerBuf, lfanew + 6);
            sizeOfOptHeader = BitConverter.ToUInt16(headerBuf, lfanew + 20);
        }
        catch (Exception) { return; }

        int sectionTableOffset = lfanew + 24 + sizeOfOptHeader;
        if (sectionTableOffset + numSections * 40 > headerRead) return;

        int textVirtualAddress = 0;
        int textVirtualSize = 0;
        bool found = false;

        for (int i = 0; i < numSections; i++)
        {
            int secOffset = sectionTableOffset + i * 40;
            if (secOffset + 40 > headerRead) break;

            string secName;
            try { secName = Encoding.ASCII.GetString(headerBuf, secOffset, 8).TrimEnd('\0'); }
            catch (Exception) { continue; }

            if (secName == ".text")
            {
                try
                {
                    textVirtualSize = BitConverter.ToInt32(headerBuf, secOffset + 8);
                    textVirtualAddress = BitConverter.ToInt32(headerBuf, secOffset + 12);
                    found = true;
                }
                catch (Exception) { }
                break;
            }
        }

        if (!found || textVirtualAddress == 0 || textVirtualSize <= 0) return;

        int readSize = Math.Min(textVirtualSize, 64 * 1024 * 1024); // cap at 64 MB
        var memBytes = new byte[readSize];
        var textBaseAddress = new IntPtr(moduleBase.ToInt64() + textVirtualAddress);

        if (!ReadProcessMemory(processHandle, textBaseAddress, memBytes, readSize, out int bytesRead)
            || bytesRead == 0)
            return;

        if (bytesRead < readSize)
        {
            var trimmed = new byte[bytesRead];
            Array.Copy(memBytes, trimmed, bytesRead);
            memBytes = trimmed;
        }

        string memHash = Convert.ToHexString(SHA256.HashData(memBytes));

        // Get on-disk hash (cached)
        string diskHash;
        if (!_diskHashes.TryGetValue(modulePath, out diskHash!))
        {
            diskHash = GetDiskTextSectionHash(modulePath);
            if (!string.IsNullOrEmpty(diskHash))
                _diskHashes[modulePath] = diskHash;
        }

        if (string.IsNullOrEmpty(diskHash)) return;

        if (!string.Equals(memHash, diskHash, StringComparison.OrdinalIgnoreCase))
        {
            var key = $"{pid}_{modulePath}";
            var now = DateTime.UtcNow;

            if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 30)
                return;

            _recentAlerts[key] = now;

            var alert = new ModuleStompingAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = procName,
                ProcessId = pid,
                ModulePath = modulePath,
                ModuleName = moduleName,
                OnDiskHash = diskHash,
                InMemoryHash = memHash,
                TextSectionSize = memBytes.Length,
                SuspicionReason = "TextSectionHashMismatch",
                Severity = 9,
                DetectedAtUtc = now
            };

            try { await _repository.AddAsync(alert, ct); }
            catch (Exception) { }

            AlertDetected?.Invoke(this, new ModuleStompingAlertEventArgs(alert));
        }
    }

    private static string GetDiskTextSectionHash(string modulePath)
    {
        try
        {
            byte[] fileBytes = System.IO.File.ReadAllBytes(modulePath);
            if (fileBytes.Length < 0x40) return string.Empty;

            int lfanew = BitConverter.ToInt32(fileBytes, 0x3C);
            if (lfanew <= 0 || lfanew + 24 + 2 >= fileBytes.Length) return string.Empty;

            int numSections = BitConverter.ToInt16(fileBytes, lfanew + 6);
            int sizeOfOptHeader = BitConverter.ToUInt16(fileBytes, lfanew + 20);
            int sectionTableOffset = lfanew + 24 + sizeOfOptHeader;

            for (int i = 0; i < numSections; i++)
            {
                int secOffset = sectionTableOffset + i * 40;
                if (secOffset + 40 > fileBytes.Length) break;

                string name = Encoding.ASCII.GetString(fileBytes, secOffset, 8).TrimEnd('\0');
                if (name == ".text")
                {
                    int rawSize = BitConverter.ToInt32(fileBytes, secOffset + 16);
                    int rawOffset = BitConverter.ToInt32(fileBytes, secOffset + 20);

                    if (rawOffset <= 0 || rawSize <= 0) return string.Empty;
                    if (rawOffset + rawSize > fileBytes.Length) return string.Empty;

                    var textBytes = new byte[rawSize];
                    Array.Copy(fileBytes, rawOffset, textBytes, 0, rawSize);
                    return Convert.ToHexString(SHA256.HashData(textBytes));
                }
            }
        }
        catch (Exception) { }

        return string.Empty;
    }
}

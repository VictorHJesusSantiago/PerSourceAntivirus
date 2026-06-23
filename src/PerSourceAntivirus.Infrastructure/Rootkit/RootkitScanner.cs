using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Rootkit;

public class RootkitScanner : IRootkitScanner
{
    private static readonly string[] SsdtFunctions =
    [
        "NtCreateFile", "NtOpenProcess", "NtReadVirtualMemory",
        "NtWriteVirtualMemory", "NtCreateProcess"
    ];

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass, IntPtr SystemInformation,
        int SystemInformationLength, out int ReturnLength);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumDeviceDrivers(
        [Out] IntPtr[] lpImageBase, int cb, out int lpcbNeeded);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetDeviceDriverFileName(
        IntPtr ImageBase, StringBuilder lpFilename, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    public Task<IReadOnlyList<RootkitFinding>> ScanAsync(CancellationToken ct = default)
    {
        var findings = new List<RootkitFinding>();
        findings.AddRange(ScanDkom());
        findings.AddRange(ScanSsdt());
        findings.AddRange(ScanHiddenDrivers());
        return Task.FromResult<IReadOnlyList<RootkitFinding>>(findings);
    }

    private List<RootkitFinding> ScanDkom()
    {
        var findings = new List<RootkitFinding>();
        var ntPids = GetPidsFromNtQuery();
        var dotNetPids = SysProcess.GetProcesses().Select(p => { int id = p.Id; p.Dispose(); return id; }).ToHashSet();
        var wmiPids = GetWmiProcessIds();

        foreach (var pid in ntPids)
        {
            if (pid == 0) continue;
            if (!dotNetPids.Contains(pid))
            {
                findings.Add(new RootkitFinding
                {
                    DetectedAtUtc = DateTime.UtcNow,
                    FindingType = RootkitFindingType.HiddenProcess,
                    Description = $"Process PID {pid} visible via NtQuerySystemInformation but hidden from Process.GetProcesses()",
                    Severity = "High",
                    ProcessId = pid
                });
            }
            else if (wmiPids.Count > 0 && !wmiPids.Contains(pid))
            {
                findings.Add(new RootkitFinding
                {
                    DetectedAtUtc = DateTime.UtcNow,
                    FindingType = RootkitFindingType.DkomManipulation,
                    Description = $"Process PID {pid} visible via NtQuerySystemInformation but hidden from WMI Win32_Process",
                    Severity = "High",
                    ProcessId = pid
                });
            }
        }

        foreach (var pid in dotNetPids)
        {
            if (pid == 0) continue;
            if (!ntPids.Contains(pid))
            {
                findings.Add(new RootkitFinding
                {
                    DetectedAtUtc = DateTime.UtcNow,
                    FindingType = RootkitFindingType.DkomManipulation,
                    Description = $"Process PID {pid} visible via Process.GetProcesses() but not in NtQuerySystemInformation",
                    Severity = "Critical",
                    ProcessId = pid
                });
            }
        }

        return findings;
    }

    private HashSet<int> GetPidsFromNtQuery()
    {
        var pids = new HashSet<int>();
        const int SystemProcessInformation = 5;
        int size = 1024 * 1024;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            int status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, out int needed);
            if (status != 0 && needed > size)
            {
                Marshal.FreeHGlobal(buffer);
                size = needed + 4096;
                buffer = Marshal.AllocHGlobal(size);
                status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, out needed);
            }
            if (status != 0) return pids;

            var offset = 0L;
            while (true)
            {
                var ptr = new IntPtr(buffer.ToInt64() + offset);
                var nextOffset = (uint)Marshal.ReadInt32(ptr, 0);
                var pid = Marshal.ReadIntPtr(ptr, 68).ToInt32(); // UniqueProcessId offset
                pids.Add(pid);
                if (nextOffset == 0) break;
                offset += nextOffset;
            }
        }
        catch
        {
            // ignore parse errors - return what we have
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return pids;
    }

    private HashSet<int> GetWmiProcessIds()
    {
        var pids = new HashSet<int>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                if (obj["ProcessId"] is uint pid)
                    pids.Add((int)pid);
                obj.Dispose();
            }
        }
        catch { }
        return pids;
    }

    private List<RootkitFinding> ScanSsdt()
    {
        var findings = new List<RootkitFinding>();
        var ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return findings;

        foreach (var funcName in SsdtFunctions)
        {
            var funcAddr = GetProcAddress(ntdll, funcName);
            if (funcAddr == IntPtr.Zero) continue;

            var bytes = new byte[20];
            try
            {
                Marshal.Copy(funcAddr, bytes, 0, 20);
            }
            catch { continue; }

            string? hookType = null;
            if (bytes[0] == 0xE9)
                hookType = "JMP relative hook";
            else if (bytes[0] == 0xFF && bytes[1] == 0x25)
                hookType = "JMP [RIP+offset] indirect hook";
            else if (!(bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8))
            {
                // Not the expected MOV R10,RCX; MOV EAX,... prologue — suspicious
                if (bytes[0] == 0x90 || bytes[0] == 0xCC || bytes[0] == 0xEB)
                    hookType = $"Suspicious prologue byte 0x{bytes[0]:X2}";
            }

            if (hookType != null)
            {
                findings.Add(new RootkitFinding
                {
                    DetectedAtUtc = DateTime.UtcNow,
                    FindingType = RootkitFindingType.SsdtHook,
                    Description = $"SSDT hook detected on {funcName}: {hookType} (bytes: {BitConverter.ToString(bytes, 0, 4)})",
                    Severity = "Critical"
                });
            }
        }

        return findings;
    }

    private List<RootkitFinding> ScanHiddenDrivers()
    {
        var findings = new List<RootkitFinding>();
        var kernelDrivers = GetKernelDriverNames();
        var wmiDrivers = GetWmiDriverNames();

        if (wmiDrivers.Count == 0) return findings;

        foreach (var driver in kernelDrivers)
        {
            if (string.IsNullOrWhiteSpace(driver)) continue;
            var shortName = Path.GetFileNameWithoutExtension(driver).ToLowerInvariant();
            if (!wmiDrivers.Contains(shortName))
            {
                findings.Add(new RootkitFinding
                {
                    DetectedAtUtc = DateTime.UtcNow,
                    FindingType = RootkitFindingType.HiddenDriver,
                    Description = $"Kernel driver '{driver}' found via EnumDeviceDrivers but not in WMI Win32_SystemDriver",
                    Severity = "High"
                });
            }
        }

        return findings;
    }

    private List<string> GetKernelDriverNames()
    {
        var names = new List<string>();
        if (!EnumDeviceDrivers([], 0, out int needed)) return names;

        var count = needed / IntPtr.Size;
        var bases = new IntPtr[count];
        if (!EnumDeviceDrivers(bases, needed, out _)) return names;

        var sb = new StringBuilder(1024);
        foreach (var imageBase in bases)
        {
            if (imageBase == IntPtr.Zero) continue;
            sb.Clear();
            if (GetDeviceDriverFileName(imageBase, sb, sb.Capacity) > 0)
                names.Add(sb.ToString());
        }
        return names;
    }

    private HashSet<string> GetWmiDriverNames()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_SystemDriver");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                if (obj["Name"] is string name)
                    names.Add(name.ToLowerInvariant());
                obj.Dispose();
            }
        }
        catch { }
        return names;
    }
}

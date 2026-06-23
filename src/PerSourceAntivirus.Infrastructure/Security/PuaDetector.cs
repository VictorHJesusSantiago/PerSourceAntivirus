using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class PuaDetector : IPuaDetector
{
    private static readonly HashSet<int> MiningPorts = [3333, 4444, 14444, 14433, 45700];
    private static readonly string[] MiningDnsPrefixes = ["pool.", "mine.", "mining."];

    private CancellationTokenSource? _cts;
    private Task? _monitorTask;

    public event EventHandler<PuaAlertEventArgs>? AlertDetected;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _monitorTask = RunScanLoopAsync(_cts.Token);
        await Task.CompletedTask;
    }

    public void StopMonitoring()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private async Task RunScanLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var alerts = await ScanAsync(ct);
                foreach (var alert in alerts)
                    AlertDetected?.Invoke(this, new PuaAlertEventArgs(alert));
            }
            catch (OperationCanceledException) { break; }
            catch { }

            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task<IReadOnlyList<PuaAlert>> ScanAsync(CancellationToken ct)
    {
        var results = new List<PuaAlert>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            DetectCryptominers(results, now);
            DetectBrowserHelperObjects(results, now);
            DetectToolbarsAndSearchHijacks(results, now);
        }, ct);

        return results;
    }

    private static void DetectCryptominers(List<PuaAlert> results, DateTime now)
    {
        var tcpConnections = GetTcpConnections();

        foreach (var process in SysProcess.GetProcesses())
        {
            try
            {
                if (IsSystemProcess(process)) continue;

                TimeSpan totalCpuTime;
                try { totalCpuTime = process.TotalProcessorTime; }
                catch { continue; }

                if (totalCpuTime.TotalSeconds < 60) continue;

                var procConnections = tcpConnections
                    .Where(c => c.OwningPid == process.Id)
                    .ToList();

                foreach (var conn in procConnections)
                {
                    if (MiningPorts.Contains(conn.RemotePort))
                    {
                        results.Add(new PuaAlert
                        {
                            Id = Guid.NewGuid(),
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            ImagePath = TryGetImagePath(process),
                            Category = "Miner",
                            DetectionReason = $"Connection to known mining port {conn.RemotePort}",
                            DetectionDetails = $"Remote: {conn.RemoteAddress}:{conn.RemotePort}, CPU time: {totalCpuTime.TotalSeconds:F0}s",
                            Severity = 8,
                            DetectedAtUtc = now
                        });
                        break;
                    }

                    if (TryResolveMiningDomain(conn.RemoteAddress, out var domain))
                    {
                        results.Add(new PuaAlert
                        {
                            Id = Guid.NewGuid(),
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            ImagePath = TryGetImagePath(process),
                            Category = "Miner",
                            DetectionReason = $"Connection to mining domain: {domain}",
                            DetectionDetails = $"Remote: {conn.RemoteAddress}:{conn.RemotePort}, CPU time: {totalCpuTime.TotalSeconds:F0}s",
                            Severity = 8,
                            DetectedAtUtc = now
                        });
                        break;
                    }
                }
            }
            catch { }
            finally
            {
                try { process.Dispose(); } catch { }
            }
        }
    }

    private static void DetectBrowserHelperObjects(List<PuaAlert> results, DateTime now)
    {
        try
        {
            const string bhoKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
            using var bhoKey = Registry.LocalMachine.OpenSubKey(bhoKeyPath);
            if (bhoKey == null) return;

            foreach (var clsid in bhoKey.GetSubKeyNames())
            {
                try
                {
                    using var clsidKey = Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsid}\InProcServer32");
                    var dllPath = clsidKey?.GetValue(null)?.ToString() ?? string.Empty;

                    if (string.IsNullOrWhiteSpace(dllPath)) continue;

                    var expanded = Environment.ExpandEnvironmentVariables(dllPath).ToLowerInvariant();
                    if (expanded.Contains(@"\program files\") || expanded.Contains(@"\program files (x86)\") ||
                        expanded.Contains(@"\windows\")) continue;

                    results.Add(new PuaAlert
                    {
                        Id = Guid.NewGuid(),
                        ProcessName = "iexplore.exe",
                        ProcessId = 0,
                        ImagePath = dllPath,
                        Category = "Adware",
                        DetectionReason = "Browser Helper Object in non-standard location",
                        DetectionDetails = $"CLSID: {clsid}, DLL: {dllPath}",
                        Severity = 6,
                        DetectedAtUtc = now
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void DetectToolbarsAndSearchHijacks(List<PuaAlert> results, DateTime now)
    {
        try
        {
            const string toolbarKeyPath = @"SOFTWARE\Microsoft\Internet Explorer\Toolbar";
            using var key = Registry.LocalMachine.OpenSubKey(toolbarKeyPath);
            if (key != null)
            {
                foreach (var valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(val)) continue;

                    if (IsKnownMicrosoftClsid(valueName)) continue;

                    results.Add(new PuaAlert
                    {
                        Id = Guid.NewGuid(),
                        ProcessName = "iexplore.exe",
                        ProcessId = 0,
                        ImagePath = string.Empty,
                        Category = "Toolbar",
                        DetectionReason = "Unknown IE toolbar registered",
                        DetectionDetails = $"CLSID: {valueName}, Value: {val}",
                        Severity = 5,
                        DetectedAtUtc = now
                    });
                }
            }
        }
        catch { }

        try
        {
            const string searchHooksPath = @"Software\Microsoft\Internet Explorer\URLSearchHooks";
            using var key = Registry.CurrentUser.OpenSubKey(searchHooksPath);
            if (key != null && key.GetValueNames().Length > 0)
            {
                foreach (var valueName in key.GetValueNames())
                {
                    if (IsKnownMicrosoftClsid(valueName)) continue;

                    results.Add(new PuaAlert
                    {
                        Id = Guid.NewGuid(),
                        ProcessName = "iexplore.exe",
                        ProcessId = 0,
                        ImagePath = string.Empty,
                        Category = "Toolbar",
                        DetectionReason = "Custom IE URL search hook registered",
                        DetectionDetails = $"Hook CLSID: {valueName}",
                        Severity = 6,
                        DetectedAtUtc = now
                    });
                }
            }
        }
        catch { }

        try
        {
            const string hijackPolicyPath = @"Software\Policies\Microsoft\Internet Explorer\Control Panel";
            using var key = Registry.CurrentUser.OpenSubKey(hijackPolicyPath);
            if (key != null && key.GetValueNames().Length > 0)
            {
                results.Add(new PuaAlert
                {
                    Id = Guid.NewGuid(),
                    ProcessName = "iexplore.exe",
                    ProcessId = 0,
                    ImagePath = string.Empty,
                    Category = "Toolbar",
                    DetectionReason = "IE control panel hijacked via registry policy",
                    DetectionDetails = $"Keys: {string.Join(", ", key.GetValueNames())}",
                    Severity = 7,
                    DetectedAtUtc = now
                });
            }
        }
        catch { }
    }

    private static bool IsSystemProcess(SysProcess process)
    {
        if (process.Id <= 4) return true;
        var name = process.ProcessName.ToLowerInvariant();
        return name is "system" or "smss" or "csrss" or "wininit" or "services" or "lsass" or "svchost";
    }

    private static string TryGetImagePath(SysProcess process)
    {
        try { return process.MainModule?.FileName ?? string.Empty; }
        catch { return string.Empty; }
    }

    private static bool TryResolveMiningDomain(string ipAddress, out string domain)
    {
        domain = string.Empty;
        try
        {
            if (!IPAddress.TryParse(ipAddress, out var addr)) return false;
            var hostEntry = Dns.GetHostEntry(addr);
            var hostName = hostEntry.HostName.ToLowerInvariant();
            foreach (var prefix in MiningDnsPrefixes)
            {
                if (hostName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    domain = hostName;
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static bool IsKnownMicrosoftClsid(string clsid)
    {
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "{02478D38-C3F9-4EFB-9B51-7695ECA05670}",
            "{2670000A-7350-4F3C-BE72-D7B1DEA87D12}",
            "{8CCCF0A3-7CCA-41A5-8B59-4D2A72A72E88}",
            "{F4CB40B0-6A0B-4B9C-A7F2-93B2C4D7A99E}"
        };
        return known.Contains(clsid);
    }

    private static List<TcpConnectionInfo> GetTcpConnections()
    {
        var result = new List<TcpConnectionInfo>();
        try
        {
            var bufferSize = 0;
            NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, 5, 0);
            var tablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (NativeMethods.GetExtendedTcpTable(tablePtr, ref bufferSize, true, 2, 5, 0) != 0)
                    return result;

                var rowCount = Marshal.ReadInt32(tablePtr);
                var rowOffset = IntPtr.Size == 8 ? 8 : 4;
                var rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();

                for (var i = 0; i < rowCount; i++)
                {
                    var rowPtr = IntPtr.Add(tablePtr, rowOffset + i * rowSize);
                    var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr));
                    var remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort);
                    result.Add(new TcpConnectionInfo(remoteIp.ToString(), remotePort, row.dwOwningPid));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tablePtr);
            }
        }
        catch { }
        return result;
    }

    private record TcpConnectionInfo(string RemoteAddress, int RemotePort, int OwningPid);

    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            int TableClass,
            uint Reserved);

        [StructLayout(LayoutKind.Sequential)]
        internal struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public int dwOwningPid;
        }
    }
}

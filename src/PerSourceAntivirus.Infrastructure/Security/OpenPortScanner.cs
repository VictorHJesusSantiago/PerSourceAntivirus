using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class OpenPortScanner : IOpenPortScanner
{
    private static readonly Dictionary<int, string> RiskPorts = new()
    {
        { 21,    "File Transfer Protocol (FTP)" },
        { 23,    "Unencrypted remote shell (Telnet)" },
        { 139,   "NetBIOS file sharing" },
        { 445,   "SMB file sharing" },
        { 1234,  "Known RAT/backdoor port" },
        { 3389,  "Remote Desktop Protocol (RDP)" },
        { 4444,  "Metasploit default listener port" },
        { 5900,  "VNC Remote Desktop" },
        { 5985,  "Windows Remote Management (WinRM) HTTP" },
        { 5986,  "Windows Remote Management (WinRM) HTTPS" },
        { 31337, "Elite/Back Orifice backdoor port" },
    };

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwSize, bool bOrder,
        int ulAf, TcpTableClass tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwSize, bool bOrder,
        int ulAf, UdpTableClass tableClass, uint reserved);

    private enum TcpTableClass { TcpTableOwnerPidAll = 5 }
    private enum UdpTableClass { UdpTableOwnerPid = 1 }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    private static readonly string[] TcpStateNames =
    [
        "UNKNOWN", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    ];

    public async Task<IReadOnlyList<OpenPortInfo>> ScanAsync(CancellationToken ct)
    {
        var results = new List<OpenPortInfo>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            ScanTcp(results, now);
            ScanUdp(results, now);
        }, ct);

        return results;
    }

    private void ScanTcp(List<OpenPortInfo> results, DateTime now)
    {
        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, TcpTableClass.TcpTableOwnerPidAll, 0);
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, true, 2, TcpTableClass.TcpTableOwnerPidAll, 0) != 0)
                return;

            var count = Marshal.ReadInt32(buf);
            var offset = IntPtr.Size == 8 ? 8 : 4;
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(IntPtr.Add(buf, offset + i * rowSize));
                var localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort);
                var remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort);
                var state = row.dwState < TcpStateNames.Length ? TcpStateNames[row.dwState] : "UNKNOWN";
                var procName = GetProcessName((int)row.dwOwningPid);

                RiskPorts.TryGetValue(localPort, out var riskDesc);
                results.Add(new OpenPortInfo
                {
                    Id = Guid.NewGuid(),
                    Protocol = "TCP",
                    LocalPort = localPort,
                    RemoteAddress = FormatIpAddress(row.dwRemoteAddr),
                    RemotePort = remotePort,
                    State = state,
                    ProcessName = procName,
                    ProcessId = (int)row.dwOwningPid,
                    IsKnownRisk = riskDesc != null,
                    RiskDescription = riskDesc ?? string.Empty,
                    ScannedAtUtc = now
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private void ScanUdp(List<OpenPortInfo> results, DateTime now)
    {
        var size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, 2, UdpTableClass.UdpTableOwnerPid, 0);
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, true, 2, UdpTableClass.UdpTableOwnerPid, 0) != 0)
                return;

            var count = Marshal.ReadInt32(buf);
            var offset = IntPtr.Size == 8 ? 8 : 4;
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(IntPtr.Add(buf, offset + i * rowSize));
                var localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort);
                var procName = GetProcessName((int)row.dwOwningPid);

                RiskPorts.TryGetValue(localPort, out var riskDesc);
                results.Add(new OpenPortInfo
                {
                    Id = Guid.NewGuid(),
                    Protocol = "UDP",
                    LocalPort = localPort,
                    RemoteAddress = string.Empty,
                    RemotePort = 0,
                    State = "LISTEN",
                    ProcessName = procName,
                    ProcessId = (int)row.dwOwningPid,
                    IsKnownRisk = riskDesc != null,
                    RiskDescription = riskDesc ?? string.Empty,
                    ScannedAtUtc = now
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string FormatIpAddress(uint addr)
    {
        try { return new IPAddress(addr).ToString(); }
        catch { return "0.0.0.0"; }
    }

    private static string GetProcessName(int pid)
    {
        try { return SysProcess.GetProcessById(pid).ProcessName; }
        catch { return string.Empty; }
    }
}

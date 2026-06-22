using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class SmbLateralMovementDetector(ISmbLateralMovementAlertRepository repository) : ISmbLateralMovementDetector
{
    // key = srcIp:srcPort -> dstIp:dstPort, tracks SMB stream state
    private readonly ConcurrentDictionary<string, SmbStreamState> _streams =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts =
        new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _running;

    public event EventHandler<SmbLateralMovementAlertEventArgs>? AlertDetected;

    private const string BpfFilter = "tcp port 445";
    private const double DedupMinutes = 5.0;

    // SMB2 constants
    private static readonly byte[] Smb2Magic = [0xFE, 0x53, 0x4D, 0x42]; // \xFE SMB
    private const int Smb2CommandOffset = 12;
    private const ushort Smb2CommandTreeConnect = 3;
    private const ushort Smb2CommandCreate = 5;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(null);
            if (device is null) return;

            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = BpfFilter;
            device.StartCapture();

            while (_running && !ct.IsCancellationRequested)
                await Task.Delay(500, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (device is not null)
            {
                try { device.StopCapture(); } catch { }
                device.OnPacketArrival -= OnPacketArrival;
                device.Close();
            }
            _running = false;
        }
    }

    public void StopMonitoring() => _running = false;

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip = packet.Extract<IPPacket>();
            var tcp = packet.Extract<TcpPacket>();
            if (ip is null || tcp is null) return;

            var srcIp = ip.SourceAddress.ToString();
            var dstIp = ip.DestinationAddress.ToString();
            var srcPort = tcp.SourcePort;
            var dstPort = tcp.DestinationPort;

            var payload = tcp.PayloadData;
            if (payload is null || payload.Length < 8) return;

            // TCP payload may contain a 4-byte NetBIOS session header before SMB2
            var smb2Offset = FindSmb2Header(payload);
            if (smb2Offset < 0 || smb2Offset + 16 > payload.Length) return;

            // Verify magic
            if (!MatchesMagic(payload, smb2Offset)) return;

            var command = (ushort)(payload[smb2Offset + Smb2CommandOffset] | (payload[smb2Offset + Smb2CommandOffset + 1] << 8));

            var streamKey = $"{srcIp}:{srcPort}->{dstIp}:{dstPort}";
            var state = _streams.GetOrAdd(streamKey, _ => new SmbStreamState(srcIp, dstIp));

            if (command == Smb2CommandTreeConnect)
            {
                var path = ExtractTreeConnectPath(payload, smb2Offset);
                if (!string.IsNullOrEmpty(path))
                {
                    if (path.Contains("IPC$", StringComparison.OrdinalIgnoreCase))
                        state.HasIpcTreeConnect = true;
                    if (path.Contains("ADMIN$", StringComparison.OrdinalIgnoreCase))
                        state.HasAdminTreeConnect = true;
                    state.LastShareName = path;
                }
            }
            else if (command == Smb2CommandCreate)
            {
                var filename = ExtractCreateFilename(payload, smb2Offset);
                if (!string.IsNullOrEmpty(filename))
                {
                    state.LastPipeName = filename;
                    if (filename.Contains("svcctl", StringComparison.OrdinalIgnoreCase))
                        state.HasSvcctlPipe = true;
                }
            }

            // PsExec detection: IPC$ tree connect + svcctl pipe creation
            if (state.HasIpcTreeConnect && state.HasSvcctlPipe)
            {
                FireAlert(srcIp, dstIp, "PsExecPattern",
                    state.LastPipeName, state.LastShareName);
                _streams.TryRemove(streamKey, out _);
                return;
            }

            // Lateral movement via ADMIN$ file copy
            if (state.HasIpcTreeConnect && state.HasAdminTreeConnect)
            {
                FireAlert(srcIp, dstIp, "AdminShareLateralMovement",
                    state.LastPipeName, state.LastShareName);
                _streams.TryRemove(streamKey, out _);
            }
        }
        catch { }
    }

    private static int FindSmb2Header(byte[] payload)
    {
        // Skip 4-byte NetBIOS session header if present
        if (payload.Length > 4 && payload[0] == 0x00)
            return 4;
        return 0;
    }

    private static bool MatchesMagic(byte[] payload, int offset)
    {
        if (offset + 4 > payload.Length) return false;
        return payload[offset] == Smb2Magic[0] &&
               payload[offset + 1] == Smb2Magic[1] &&
               payload[offset + 2] == Smb2Magic[2] &&
               payload[offset + 3] == Smb2Magic[3];
    }

    private static string ExtractTreeConnectPath(byte[] payload, int smb2Offset)
    {
        try
        {
            // SMB2 TreeConnect request: StructureSize(2) + Reserved(2) + PathOffset(2) + PathLength(2) = 8 bytes after header
            // Header is 64 bytes for SMB2
            var structStart = smb2Offset + 64;
            if (structStart + 8 > payload.Length) return string.Empty;

            var pathOffset = (ushort)(payload[structStart + 4] | (payload[structStart + 5] << 8));
            var pathLength = (ushort)(payload[structStart + 6] | (payload[structStart + 7] << 8));

            var absoluteOffset = smb2Offset + pathOffset;
            if (absoluteOffset < 0 || absoluteOffset + pathLength > payload.Length || pathLength == 0)
                return string.Empty;

            return Encoding.Unicode.GetString(payload, absoluteOffset, pathLength);
        }
        catch { return string.Empty; }
    }

    private static string ExtractCreateFilename(byte[] payload, int smb2Offset)
    {
        try
        {
            // SMB2 Create request header is 64 bytes, then StructureSize(2) + SecurityFlags(1) + RequestedOplockLevel(1) +
            // ImpersonationLevel(4) + SmbCreateFlags(8) + Reserved(8) + DesiredAccess(4) + FileAttributes(4) +
            // ShareAccess(4) + CreateDisposition(4) + CreateOptions(4) + NameOffset(2) + NameLength(2) = total 56 bytes
            var structStart = smb2Offset + 64;
            if (structStart + 56 > payload.Length) return string.Empty;

            var nameOffset = (ushort)(payload[structStart + 44] | (payload[structStart + 45] << 8));
            var nameLength = (ushort)(payload[structStart + 46] | (payload[structStart + 47] << 8));

            var absoluteOffset = smb2Offset + nameOffset;
            if (absoluteOffset < 0 || absoluteOffset + nameLength > payload.Length || nameLength == 0)
                return string.Empty;

            return Encoding.Unicode.GetString(payload, absoluteOffset, nameLength);
        }
        catch { return string.Empty; }
    }

    private void FireAlert(string sourceIp, string targetIp, string reason, string pipeName, string shareName)
    {
        var key = $"{sourceIp}->{targetIp}_{reason}";
        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < DedupMinutes) return;
        _recentAlerts[key] = now;

        var alert = new SmbLateralMovementAlert
        {
            Id = Guid.NewGuid(),
            SourceIp = sourceIp,
            TargetIp = targetIp,
            DetectionReason = reason,
            PipeName = pipeName,
            ShareName = shareName,
            Severity = 9,
            DetectedAtUtc = now
        };

        try { repository.AddAsync(alert).GetAwaiter().GetResult(); } catch { }
        AlertDetected?.Invoke(this, new SmbLateralMovementAlertEventArgs(alert));
    }

    private static ILiveDevice? GetDevice(string? deviceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) return null;
            if (deviceName is not null)
                return devices.FirstOrDefault(d => d.Name == deviceName);
            return devices[0];
        }
        catch { return null; }
    }

    private sealed class SmbStreamState(string srcIp, string dstIp)
    {
        public string SourceIp { get; } = srcIp;
        public string DestinationIp { get; } = dstIp;
        public bool HasIpcTreeConnect { get; set; }
        public bool HasAdminTreeConnect { get; set; }
        public bool HasSvcctlPipe { get; set; }
        public string LastShareName { get; set; } = string.Empty;
        public string LastPipeName { get; set; } = string.Empty;
    }
}

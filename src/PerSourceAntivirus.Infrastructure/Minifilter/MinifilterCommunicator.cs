using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Minifilter;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct FilterMessageHeader
{
    public uint ReplyLength;
    public ulong MessageId;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct FilterReplyHeader
{
    public int Status;
    public ulong MessageId;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct PsavNotification
{
    public FilterMessageHeader Header;
    public uint BytesToScan;
    public uint Flags;
    public fixed char FileName[512];
    public fixed byte Contents[4096];
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct PsavReply
{
    public FilterReplyHeader Header;
    public byte SafeToOpen;
    public byte Pad0;
    public byte Pad1;
    public byte Pad2;
}

public class MinifilterCommunicator(IYaraScanner yaraScanner) : IMinifilterMonitor
{
    private const string PortName = @"\PSAVScanPort";

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        nint lpContext,
        ushort wSizeOfContext,
        nint lpSecurityAttributes,
        out SafeFileHandle hPort);

    [DllImport("fltlib.dll", SetLastError = false)]
    private static extern unsafe int FilterGetMessage(
        SafeFileHandle hPort,
        PsavNotification* lpMessageBuffer,
        uint dwMessageBufferSize,
        nint lpOverlapped);

    [DllImport("fltlib.dll", SetLastError = false)]
    private static extern unsafe int FilterReplyMessage(
        SafeFileHandle hPort,
        PsavReply* lpReplyBuffer,
        uint dwReplyBufferSize);

    public async IAsyncEnumerable<MinifilterEvent> WatchAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var hr = FilterConnectCommunicationPort(PortName, 0, nint.Zero, 0, nint.Zero, out var hPort);
        if (hr != 0)
            throw new InvalidOperationException(
                $"Cannot connect to minifilter port '{PortName}'. " +
                $"HRESULT=0x{hr:X8}. Ensure the driver is loaded and this process runs as admin.");

        using (hPort)
        {
            await foreach (var ev in StreamEventsAsync(hPort, ct))
                yield return ev;
        }
    }

    private async IAsyncEnumerable<MinifilterEvent> StreamEventsAsync(
        SafeFileHandle hPort,
        [EnumeratorCancellation] CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            MinifilterEvent? ev;
            try
            {
                ev = await Task.Run(() => ReceiveAndReply(hPort, ct), ct);
            }
            catch (OperationCanceledException) { yield break; }
            catch (Exception ex)
            {
                if (ex is ExternalException { ErrorCode: unchecked((int)0x80070006) } ||
                    ex.Message.Contains("invalid handle", StringComparison.OrdinalIgnoreCase))
                    yield break;
                throw;
            }

            if (ev is not null)
                yield return ev;
        }
    }

    private unsafe MinifilterEvent? ReceiveAndReply(SafeFileHandle hPort, CancellationToken ct)
    {
        var notification = new PsavNotification();
        var hr = FilterGetMessage(hPort, &notification,
            (uint)sizeof(PsavNotification), nint.Zero);

        ct.ThrowIfCancellationRequested();

        if (hr != 0)
            throw new ExternalException($"FilterGetMessage HRESULT=0x{hr:X8}", hr);

        var filePath = new string(notification.FileName);
        var nullIdx = filePath.IndexOf('\0');
        if (nullIdx >= 0) filePath = filePath[..nullIdx];

        var bytesToScan = (int)Math.Min(notification.BytesToScan, 4096u);
        var contents = new byte[bytesToScan];
        for (var j = 0; j < bytesToScan; j++)
            contents[j] = notification.Contents[j];

        var matches = bytesToScan > 0 ? yaraScanner.ScanMemory(contents) : [];
        var blocked = matches.Count > 0;
        var blockReason = blocked
            ? string.Join(", ", matches.Select(m => m.RuleIdentifier))
            : null;

        var reply = new PsavReply
        {
            Header = new FilterReplyHeader
            {
                Status = 0,
                MessageId = notification.Header.MessageId
            },
            SafeToOpen = blocked ? (byte)0 : (byte)1
        };
        FilterReplyMessage(hPort, &reply, (uint)sizeof(PsavReply));

        return new MinifilterEvent(DateTime.UtcNow, filePath, 0, blocked, blockReason);
    }
}

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Minifilter;

// Matches PSAV_KERNEL_EVENT in PerSourceAntivirus.Driver.c (pack 1)
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct PsavKernelEvent
{
    public FilterMessageHeader Header;   // 12 bytes (reuse from MinifilterCommunicator)
    public uint EventType;               //  4 bytes
    public uint ProcessId;               //  4 bytes
    public uint ParentProcessId;         //  4 bytes
    public uint AccessMaskStripped;      //  4 bytes
    public ulong ImageBase;              //  8 bytes
    public fixed char ImagePath[512];    // 1024 bytes
    public fixed char CommandLine[256];  //  512 bytes
    // Total: 1572 bytes
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct PsavKernelEventReply
{
    public FilterReplyHeader Header;     // 12 bytes
    public uint Acknowledged;            //  4 bytes
}

public class KernelEventCommunicator(IYaraScanner? yaraScanner = null) : IKernelEventMonitor
{
    private const string EventPortName = @"\PSAVEventPort";

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, nint lpContext,
        ushort wSizeOfContext, nint lpSecurityAttributes, out SafeFileHandle hPort);

    [DllImport("fltlib.dll")]
    private static extern unsafe int FilterGetMessage(
        SafeFileHandle hPort, PsavKernelEvent* lpMessageBuffer,
        uint dwMessageBufferSize, nint lpOverlapped);

    [DllImport("fltlib.dll")]
    private static extern unsafe int FilterReplyMessage(
        SafeFileHandle hPort, PsavKernelEventReply* lpReplyBuffer,
        uint dwReplyBufferSize);

    public async IAsyncEnumerable<KernelEvent> WatchAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var hr = FilterConnectCommunicationPort(EventPortName, 0, nint.Zero, 0, nint.Zero, out var hPort);
        if (hr != 0)
            throw new InvalidOperationException(
                $"Cannot connect to kernel event port '{EventPortName}'. " +
                $"HRESULT=0x{hr:X8}. Ensure the driver is loaded and running as admin.");

        using (hPort)
        {
            while (!ct.IsCancellationRequested)
            {
                KernelEvent? ev;
                try
                {
                    ev = await Task.Run(() => ReceiveEvent(hPort, ct), ct);
                }
                catch (OperationCanceledException) { yield break; }
                catch (ExternalException ex) when (ex.ErrorCode is unchecked((int)0x80070006) or -1)
                {
                    yield break; // driver unloaded
                }

                if (ev is not null)
                    yield return ev;
            }
        }
    }

    private unsafe KernelEvent? ReceiveEvent(SafeFileHandle hPort, CancellationToken ct)
    {
        var msg = new PsavKernelEvent();
        var hr = FilterGetMessage(hPort, &msg, (uint)sizeof(PsavKernelEvent), nint.Zero);

        ct.ThrowIfCancellationRequested();
        if (hr != 0)
            throw new ExternalException($"FilterGetMessage (event) HRESULT=0x{hr:X8}", hr);

        // Acknowledge immediately
        var reply = new PsavKernelEventReply
        {
            Header = new FilterReplyHeader { Status = 0, MessageId = msg.Header.MessageId },
            Acknowledged = 1
        };
        FilterReplyMessage(hPort, &reply, (uint)sizeof(PsavKernelEventReply));

        var imagePath = ExtractString(msg.ImagePath, 512);
        var cmdLine   = ExtractString(msg.CommandLine, 256);

        return new KernelEvent(
            DateTime.UtcNow,
            (KernelEventType)msg.EventType,
            (int)msg.ProcessId,
            (int)msg.ParentProcessId,
            imagePath,
            string.IsNullOrEmpty(cmdLine) ? null : cmdLine,
            msg.ImageBase,
            msg.AccessMaskStripped);
    }

    private static unsafe string ExtractString(char* buffer, int maxChars)
    {
        var s = new string(buffer);
        var nullIdx = s.IndexOf('\0');
        return nullIdx >= 0 ? s[..nullIdx] : s;
    }
}

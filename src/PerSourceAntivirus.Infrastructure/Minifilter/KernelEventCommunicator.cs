using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Minifilter;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct PsavKernelEvent
{
    public FilterMessageHeader Header;
    public uint EventType;
    public uint ProcessId;
    public uint ParentProcessId;
    public uint AccessMaskStripped;
    public ulong ImageBase;
    public fixed char ImagePath[512];
    public fixed char CommandLine[256];
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct PsavKernelEventReply
{
    public FilterReplyHeader Header;
    public uint Acknowledged;
}

public class KernelEventCommunicator : IKernelEventMonitor
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
                    yield break;
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

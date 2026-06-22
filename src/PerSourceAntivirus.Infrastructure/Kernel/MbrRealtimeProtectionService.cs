using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Kernel;

[SupportedOSPlatform("windows")]
public sealed class MbrRealtimeProtectionService : IMbrRealtimeProtection
{
    private readonly IMbrSnapshotRepository _snapshotRepo;
    private readonly IMbrWriteAttemptRepository _writeAttemptRepo;
    private volatile bool _active;
    private IntPtr _driveHandle = new IntPtr(-1);
    private byte[]? _baseline;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;
    private const int MBR_SIZE = 512;

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    public event EventHandler<MbrWriteAttemptEventArgs>? WriteAttemptDetected;

    public bool IsActive => _active;

    public MbrRealtimeProtectionService(IMbrSnapshotRepository snapshotRepo, IMbrWriteAttemptRepository writeAttemptRepo)
    {
        _snapshotRepo = snapshotRepo;
        _writeAttemptRepo = writeAttemptRepo;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        _active = true;

        _driveHandle = CreateFile(
            @"\\.\PhysicalDrive0",
            GENERIC_READ,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        _baseline = ReadSector();

        try
        {
            while (!ct.IsCancellationRequested && _active)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);

                if (ct.IsCancellationRequested)
                    break;

                try
                {
                    var current = ReadSector();
                    if (current is not null && _baseline is not null && !current.SequenceEqual(_baseline))
                    {
                        _baseline = current;
                        await FireWriteAttemptAsync(ct);
                    }
                }
                catch { }
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            _active = false;
            if (_driveHandle != IntPtr.Zero && _driveHandle != new IntPtr(-1))
            {
                CloseHandle(_driveHandle);
                _driveHandle = new IntPtr(-1);
            }
        }
    }

    public void Stop()
    {
        _active = false;
        if (_driveHandle != IntPtr.Zero && _driveHandle != new IntPtr(-1))
        {
            CloseHandle(_driveHandle);
            _driveHandle = new IntPtr(-1);
        }
    }

    private byte[]? ReadSector()
    {
        if (_driveHandle == IntPtr.Zero || _driveHandle == new IntPtr(-1))
        {
            try
            {
                using var fs = new FileStream(@"\\.\PhysicalDrive0",
                    FileMode.Open, FileAccess.Read, FileShare.ReadWrite, MBR_SIZE);
                var buf = new byte[MBR_SIZE];
                var read = fs.Read(buf, 0, MBR_SIZE);
                if (read < MBR_SIZE)
                    return null;
                return buf;
            }
            catch
            {
                return null;
            }
        }

        var buffer = new byte[MBR_SIZE];
        if (!ReadFile(_driveHandle, buffer, MBR_SIZE, out var bytesRead, IntPtr.Zero))
            return null;
        if (bytesRead < MBR_SIZE)
            return null;
        return buffer;
    }

    private async Task FireWriteAttemptAsync(CancellationToken ct)
    {
        var alert = new MbrWriteAttemptAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = "Unknown",
            ProcessId = 0,
            DriveNumber = 0,
            Sector = 0,
            WasBlocked = false,
            DetectionMethod = "MBR-PollingCheck",
            Severity = 10,
            DetectedAtUtc = DateTime.UtcNow
        };

        try { await _writeAttemptRepo.AddAsync(alert, ct); } catch { }
        WriteAttemptDetected?.Invoke(this, new MbrWriteAttemptEventArgs(alert));
    }
}

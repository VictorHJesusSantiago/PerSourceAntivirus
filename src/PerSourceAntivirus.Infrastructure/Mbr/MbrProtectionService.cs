using System.Security.Cryptography;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Mbr;

// Reads the first sector (512 bytes) of a physical drive and returns its SHA-256 hash.
// Requires administrator privileges; uses FileStream with the physical device path.
public sealed class MbrProtectionService : IMbrProtectionService
{
    private const int MbrSectorSize = 512;

    public async Task<MbrReadResult> ReadMbrHashAsync(
        int driveIndex = 0, CancellationToken cancellationToken = default)
    {
        var devicePath = $@"\\.\PhysicalDrive{driveIndex}";
        try
        {
            await using var stream = new FileStream(
                devicePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                MbrSectorSize,
                FileOptions.None);

            var buffer = new byte[MbrSectorSize];
            var read = await stream.ReadAsync(buffer.AsMemory(0, MbrSectorSize), cancellationToken);
            if (read < MbrSectorSize)
                Array.Resize(ref buffer, read);

            var hash = Convert.ToHexString(SHA256.HashData(buffer)).ToLowerInvariant();
            return new MbrReadResult(hash, read, true);
        }
        catch (UnauthorizedAccessException)
        {
            return new MbrReadResult(null, 0, false,
                $"Access denied reading {devicePath}. Run as administrator.");
        }
        catch (Exception ex)
        {
            return new MbrReadResult(null, 0, false, ex.Message);
        }
    }
}

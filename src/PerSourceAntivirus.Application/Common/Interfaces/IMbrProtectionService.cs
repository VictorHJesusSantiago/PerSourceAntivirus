namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMbrProtectionService
{
    Task<MbrReadResult> ReadMbrHashAsync(int driveIndex = 0, CancellationToken cancellationToken = default);
}

public record MbrReadResult(string? Sha256Hash, int SectorSize, bool Success, string? ErrorMessage = null);

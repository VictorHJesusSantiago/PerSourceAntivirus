namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBlocklistUpdater
{
    Task<BlocklistUpdateResult> UpdateAsync(CancellationToken cancellationToken = default);
}

public record BlocklistUpdateResult(int IpsAdded, int IpsTotal, string Source, bool Success, string? ErrorMessage = null);

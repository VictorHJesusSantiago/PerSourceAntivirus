namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBlocklistProvider
{
    bool TryGetBlockReason(string ipAddress, out string? reason);
    void Reload();
}

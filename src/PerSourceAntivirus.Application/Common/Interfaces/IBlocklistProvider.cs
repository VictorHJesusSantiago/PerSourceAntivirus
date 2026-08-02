namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBlocklistProvider
{
    bool TryGetBlockReason(string ipAddress, out string? reason);
    void Reload();

    // Enumerates every blocked IP so callers can push the list somewhere else (e.g. sync into
    // WFP filters). Without this, consumers could only ask "is this one IP blocked?" and had no
    // way to act on the blocklist as a whole.
    IReadOnlyCollection<string> GetAllBlockedAddresses();
}

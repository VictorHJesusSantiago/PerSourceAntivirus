namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IGeoIpBlockingService
{
    bool IsBlockedCountry(string ipAddress, out string? countryCode);
    string? LookupCountry(string ipAddress);
    IReadOnlySet<string> BlockedCountries { get; }
    void ReloadDatabase();
}

namespace PerSourceAntivirus.Application.Common.Interfaces;

// Looks up the country for an IPv4 address against a locally-supplied CSV range database
// (format: start_ip,end_ip,country_code — e.g. an exported GeoLite2 country CSV) and checks
// it against an administrator-configured list of blocked country codes.
public interface IGeoIpBlockingService
{
    bool IsBlockedCountry(string ipAddress, out string? countryCode);
    string? LookupCountry(string ipAddress);
    IReadOnlySet<string> BlockedCountries { get; }
    void ReloadDatabase();
}

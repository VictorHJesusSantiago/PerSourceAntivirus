using System.Net;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class GeoIpBlockingService : IGeoIpBlockingService
{
    private readonly string _databaseFile;
    private readonly object _lock = new();
    private (uint start, uint end, string country)[] _ranges = [];

    public IReadOnlySet<string> BlockedCountries { get; }

    public GeoIpBlockingService(string databaseFile, IEnumerable<string> blockedCountries)
    {
        _databaseFile = databaseFile;
        BlockedCountries = blockedCountries
            .Select(c => c.Trim().ToUpperInvariant())
            .Where(c => c.Length > 0)
            .ToHashSet();
        ReloadDatabase();
    }

    public void ReloadDatabase()
    {
        var ranges = new List<(uint start, uint end, string country)>();
        if (File.Exists(_databaseFile))
        {
            foreach (var line in File.ReadAllLines(_databaseFile))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;

                var parts = trimmed.Split(',');
                if (parts.Length != 3) continue;
                if (!TryToUint32(parts[0].Trim(), out var start)) continue;
                if (!TryToUint32(parts[1].Trim(), out var end)) continue;

                var country = parts[2].Trim().ToUpperInvariant();
                if (country.Length == 0) continue;

                ranges.Add((start, end, country));
            }
            ranges.Sort((a, b) => a.start.CompareTo(b.start));
        }

        lock (_lock) { _ranges = ranges.ToArray(); }
    }

    public bool IsBlockedCountry(string ipAddress, out string? countryCode)
    {
        countryCode = LookupCountry(ipAddress);
        return countryCode is not null && BlockedCountries.Contains(countryCode);
    }

    public string? LookupCountry(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed) ||
            parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return null;

        var bytes = parsed.GetAddressBytes();
        uint ip = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);

        (uint start, uint end, string country)[] ranges;
        lock (_lock) { ranges = _ranges; }

        int lo = 0, hi = ranges.Length - 1;
        while (lo <= hi)
        {
            int mid = lo + (hi - lo) / 2;
            var range = ranges[mid];
            if (ip < range.start) hi = mid - 1;
            else if (ip > range.end) lo = mid + 1;
            else return range.country;
        }

        return null;
    }

    private static bool TryToUint32(string ip, out uint value)
    {
        value = 0;
        if (!IPAddress.TryParse(ip, out var parsed) ||
            parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bytes = parsed.GetAddressBytes();
        value = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
        return true;
    }
}

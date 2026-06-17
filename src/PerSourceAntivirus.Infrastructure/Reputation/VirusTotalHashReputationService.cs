using System.Net;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Reputation;

public class VirusTotalHashReputationService : IHashReputationService
{
    private static readonly HttpClient Http = new();
    private readonly string _apiKey;

    public VirusTotalHashReputationService(string apiKey)
    {
        _apiKey = apiKey;
    }

    public async Task<HashReputationData?> CheckAsync(string sha256, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_apiKey)) return null;

        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
        request.Headers.Add("x-apikey", _apiKey);

        HttpResponseMessage response;
        try
        {
            response = await Http.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException)
        {
            return null;
        }

        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        if (!response.IsSuccessStatusCode) return null;

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        try
        {
            using var doc = JsonDocument.Parse(json);
            var stats = doc.RootElement
                .GetProperty("data")
                .GetProperty("attributes")
                .GetProperty("last_analysis_stats");

            var malicious = stats.GetProperty("malicious").GetInt32();
            var suspicious = stats.GetProperty("suspicious").GetInt32();
            var harmless = stats.GetProperty("harmless").GetInt32();
            var undetected = stats.GetProperty("undetected").GetInt32();
            var total = malicious + suspicious + harmless + undetected;

            return new HashReputationData(
                malicious + suspicious,
                total,
                malicious > 0,
                "VirusTotal",
                $"https://www.virustotal.com/gui/file/{sha256}");
        }
        catch (KeyNotFoundException) { return null; }
        catch (JsonException) { return null; }
    }
}

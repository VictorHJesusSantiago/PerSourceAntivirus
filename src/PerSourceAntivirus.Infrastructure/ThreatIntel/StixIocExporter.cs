using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.ThreatIntel;

public sealed class StixIocExporter(ICustomIocRepository customIocRepository, IStixIocRepository stixIocRepository)
    : IStixIocExporter
{
    public async Task<string> ExportToFileAsync(string outputFilePath, CancellationToken ct = default)
    {
        var customIocs = await customIocRepository.GetAllAsync(ct).ConfigureAwait(false);
        var importedIocs = await stixIocRepository.GetAllAsync(ct).ConfigureAwait(false);

        var objects = new List<object>();

        foreach (var ioc in customIocs.Where(i => i.IsActive))
        {
            objects.Add(new
            {
                type = "indicator",
                spec_version = "2.1",
                id = $"indicator--{ioc.Id}",
                created = ioc.CreatedAtUtc.ToString("O"),
                modified = (ioc.LastMatchedAtUtc ?? ioc.CreatedAtUtc).ToString("O"),
                name = ioc.Description,
                pattern = BuildStixPattern(ioc.IocType, ioc.Value),
                pattern_type = "stix",
                valid_from = ioc.CreatedAtUtc.ToString("O"),
                labels = ioc.Tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            });
        }

        foreach (var ioc in importedIocs)
        {
            objects.Add(new
            {
                type = "indicator",
                spec_version = "2.1",
                id = $"indicator--{ioc.Id}",
                created = ioc.CreatedAtUtc.ToString("O"),
                modified = ioc.CreatedAtUtc.ToString("O"),
                name = $"Re-exported {ioc.IocType} indicator",
                pattern = BuildStixPattern(ioc.IocType, ioc.Value),
                pattern_type = "stix",
                valid_from = ioc.CreatedAtUtc.ToString("O"),
                confidence = (int)Math.Round(ioc.Confidence),
                labels = ioc.Labels.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            });
        }

        var bundle = new
        {
            type = "bundle",
            id = $"bundle--{Guid.NewGuid()}",
            objects
        };

        var json = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });

        var dir = Path.GetDirectoryName(outputFilePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(outputFilePath, json, ct).ConfigureAwait(false);

        return outputFilePath;
    }

    private static string BuildStixPattern(string iocType, string value)
    {
        var lowerType = iocType.ToLowerInvariant();
        return lowerType switch
        {
            "hash" or "sha256" => $"[file:hashes.'SHA-256' = '{Escape(value)}']",
            "ip" or "ipv4" => $"[ipv4-addr:value = '{Escape(value)}']",
            "domain" or "hostname" => $"[domain-name:value = '{Escape(value)}']",
            "url" => $"[url:value = '{Escape(value)}']",
            _ => $"[x-psav:indicator_value = '{Escape(value)}']"
        };
    }

    private static string Escape(string value) => value.Replace("'", "\\'");
}

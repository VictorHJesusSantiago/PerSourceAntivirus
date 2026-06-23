using System.Text.Json;
using System.Text.RegularExpressions;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.ThreatIntel;

public sealed class StixFeedImporter : IStixFeedImporter
{
    private static readonly Regex IpPatternRegex     = new(@"\[ipv4-addr:value\s*=\s*'([^']+)'\]",     RegexOptions.Compiled);
    private static readonly Regex DomainPatternRegex = new(@"\[domain-name:value\s*=\s*'([^']+)'\]",   RegexOptions.Compiled);
    private static readonly Regex HashPatternRegex   = new(@"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", RegexOptions.Compiled);

    private readonly IStixFeedSourceRepository _feedRepo;
    private readonly IStixIocRepository        _iocRepo;
    private readonly HttpClient                _http;

    public StixFeedImporter(IStixFeedSourceRepository feedRepo, IStixIocRepository iocRepo, HttpClient http)
    {
        _feedRepo = feedRepo;
        _iocRepo  = iocRepo;
        _http     = http;
    }

    public async Task<int> ImportFromUrlAsync(string url, string feedName, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(30));

        string json;
        try
        {
            json = await _http.GetStringAsync(url, cts.Token);
        }
        catch (Exception)
        {
            return 0;
        }

        var feedId = Guid.NewGuid();
        var iocs   = new List<StixIoc>();

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("type", out var typeEl) && typeEl.GetString() == "bundle")
            {
                if (root.TryGetProperty("objects", out var objectsEl) && objectsEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var obj in objectsEl.EnumerateArray())
                    {
                        try
                        {
                            if (!obj.TryGetProperty("type", out var objType) || objType.GetString() != "indicator")
                                continue;

                            if (!obj.TryGetProperty("pattern", out var patternEl))
                                continue;

                            var pattern    = patternEl.GetString() ?? string.Empty;
                            var confidence = obj.TryGetProperty("confidence", out var confEl) ? confEl.GetDouble() : 50.0;
                            var labels     = string.Empty;
                            if (obj.TryGetProperty("labels", out var labelsEl) && labelsEl.ValueKind == JsonValueKind.Array)
                                labels = string.Join(",", labelsEl.EnumerateArray().Select(l => l.GetString() ?? string.Empty));

                            var extracted = ExtractFromPattern(pattern, feedId, confidence, labels);
                            iocs.AddRange(extracted);
                        }
                        catch { }
                    }
                }
            }
            else if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in root.EnumerateArray())
                {
                    try
                    {
                        var iocType  = item.TryGetProperty("type", out var t) ? t.GetString() ?? string.Empty : string.Empty;
                        var value    = item.TryGetProperty("value", out var v) ? v.GetString() ?? string.Empty : string.Empty;

                        if (string.IsNullOrEmpty(value))
                            continue;

                        var normalizedType = iocType.ToUpperInvariant() switch
                        {
                            "MD5" or "SHA1" or "SHA256" or "HASH" => "Hash",
                            "IP"  or "IPV4" or "IPV6"             => "IP",
                            "DOMAIN" or "URL" or "HOSTNAME"        => "Domain",
                            _ => iocType,
                        };

                        iocs.Add(new StixIoc
                        {
                            Id           = Guid.NewGuid(),
                            FeedSourceId = feedId,
                            IocType      = normalizedType,
                            Value        = value,
                            Labels       = string.Empty,
                            Confidence   = 50.0,
                            ThreatActors = string.Empty,
                            CreatedAtUtc = DateTime.UtcNow,
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }

        var feedSource = new StixFeedSource
        {
            Id                = feedId,
            Name              = feedName,
            Url               = url,
            FeedType          = "STIX",
            IsEnabled         = true,
            LastUpdatedAtUtc  = DateTime.UtcNow,
            LastStatus        = iocs.Count > 0 ? "Success" : "Empty",
            IocCount          = iocs.Count,
        };

        try
        {
            await _feedRepo.AddAsync(feedSource, ct);
            if (iocs.Count > 0)
                await _iocRepo.AddRangeAsync(iocs, ct);
        }
        catch { }

        return iocs.Count;
    }

    public Task<IReadOnlyList<StixFeedSource>> GetFeedSourcesAsync(CancellationToken ct = default)
        => _feedRepo.GetAllAsync(ct);

    public Task<IReadOnlyList<StixIoc>> GetIocsAsync(Guid? feedId, CancellationToken ct = default)
        => feedId.HasValue ? _iocRepo.GetByFeedAsync(feedId.Value, ct) : _iocRepo.GetAllAsync(ct);

    private static IEnumerable<StixIoc> ExtractFromPattern(string pattern, Guid feedId, double confidence, string labels)
    {
        var ipMatch = IpPatternRegex.Match(pattern);
        if (ipMatch.Success)
        {
            yield return new StixIoc
            {
                Id           = Guid.NewGuid(),
                FeedSourceId = feedId,
                IocType      = "IP",
                Value        = ipMatch.Groups[1].Value,
                Labels       = labels,
                Confidence   = confidence,
                ThreatActors = string.Empty,
                CreatedAtUtc = DateTime.UtcNow,
            };
            yield break;
        }

        var domainMatch = DomainPatternRegex.Match(pattern);
        if (domainMatch.Success)
        {
            yield return new StixIoc
            {
                Id           = Guid.NewGuid(),
                FeedSourceId = feedId,
                IocType      = "Domain",
                Value        = domainMatch.Groups[1].Value,
                Labels       = labels,
                Confidence   = confidence,
                ThreatActors = string.Empty,
                CreatedAtUtc = DateTime.UtcNow,
            };
            yield break;
        }

        var hashMatch = HashPatternRegex.Match(pattern);
        if (hashMatch.Success)
        {
            yield return new StixIoc
            {
                Id           = Guid.NewGuid(),
                FeedSourceId = feedId,
                IocType      = "Hash",
                Value        = hashMatch.Groups[1].Value,
                Labels       = labels,
                Confidence   = confidence,
                ThreatActors = string.Empty,
                CreatedAtUtc = DateTime.UtcNow,
            };
        }
    }
}

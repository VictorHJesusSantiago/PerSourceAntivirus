using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class InstalledSoftwareScanner : IInstalledSoftwareScanner
{
    private static readonly string[] RegistryPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ];

    private readonly HttpClient _httpClient;

    public InstalledSoftwareScanner()
    {
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PerSourceAntivirus/1.0");
    }

    public async Task<IReadOnlyList<VulnerableSoftwareAlert>> ScanInstalledSoftwareAsync(CancellationToken ct)
    {
        var softwareList = ReadInstalledSoftware();
        var alerts = new List<VulnerableSoftwareAlert>();

        foreach (var (name, version, publisher) in softwareList)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var cpe = BuildCpe(publisher, name, version);
                var cves = await QueryNvdAsync(cpe, ct);
                alerts.AddRange(cves.Select(cve => new VulnerableSoftwareAlert
                {
                    Id = Guid.NewGuid(),
                    SoftwareName = name,
                    SoftwareVersion = version,
                    CpeUri = cpe,
                    CveId = cve.CveId,
                    CvssScore = cve.CvssScore,
                    CvssVector = cve.CvssVector,
                    Description = cve.Description,
                    Severity = cve.CvssScore >= 9.0 ? 10 : 7,
                    DetectedAtUtc = DateTime.UtcNow
                }));

                await Task.Delay(1000, ct);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                await Task.Delay(1000, ct);
            }
        }

        return alerts.AsReadOnly();
    }

    private static List<(string Name, string Version, string Publisher)> ReadInstalledSoftware()
    {
        var result = new List<(string, string, string)>();

        foreach (var path in RegistryPaths)
        {
            try
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = hive.OpenSubKey(path);
                if (key == null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        if (subKey == null) continue;

                        var name = subKey.GetValue("DisplayName") as string;
                        var version = subKey.GetValue("DisplayVersion") as string;
                        var publisher = subKey.GetValue("Publisher") as string;

                        if (string.IsNullOrWhiteSpace(name)) continue;

                        result.Add((
                            name.Trim(),
                            (version ?? "").Trim(),
                            (publisher ?? "").Trim()
                        ));
                    }
                    catch { }
                }
            }
            catch { }
        }

        return result;
    }

    private static string BuildCpe(string publisher, string name, string version)
    {
        var normPublisher = NormalizeCpeComponent(publisher);
        var normName = NormalizeCpeComponent(name);
        var normVersion = NormalizeCpeComponent(version);
        if (string.IsNullOrEmpty(normVersion)) normVersion = "*";
        return $"cpe:2.3:a:{normPublisher}:{normName}:{normVersion}:*:*:*:*:*:*:*";
    }

    private static string NormalizeCpeComponent(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "_";
        var lower = value.ToLowerInvariant().Trim();
        var noSpaces = lower.Replace(' ', '_');
        var cleaned = Regex.Replace(noSpaces, @"[^a-z0-9_\.\-]", "");
        return string.IsNullOrEmpty(cleaned) ? "_" : cleaned;
    }

    private async Task<List<(string CveId, double CvssScore, string CvssVector, string Description)>> QueryNvdAsync(
        string cpe, CancellationToken ct)
    {
        var results = new List<(string, double, string, string)>();
        var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={Uri.EscapeDataString(cpe)}&cvssV3Severity=HIGH";

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.GetAsync(url, ct);
        }
        catch
        {
            return results;
        }

        if ((int)response.StatusCode == 429)
        {
            await Task.Delay(30000, ct);
            try
            {
                response = await _httpClient.GetAsync(url, ct);
            }
            catch
            {
                return results;
            }
        }

        if (!response.IsSuccessStatusCode)
            return results;

        string json;
        try
        {
            json = await response.Content.ReadAsStringAsync(ct);
        }
        catch
        {
            return results;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulnerabilities))
                return results;

            foreach (var vuln in vulnerabilities.EnumerateArray())
            {
                try
                {
                    if (!vuln.TryGetProperty("cve", out var cve)) continue;

                    var cveId = cve.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "" : "";

                    var description = "";
                    if (cve.TryGetProperty("descriptions", out var descs))
                    {
                        foreach (var desc in descs.EnumerateArray())
                        {
                            if (desc.TryGetProperty("lang", out var langEl) && langEl.GetString() == "en")
                            {
                                if (desc.TryGetProperty("value", out var valEl))
                                {
                                    description = valEl.GetString() ?? "";
                                    break;
                                }
                            }
                        }
                    }

                    double cvssScore = 0;
                    string cvssVector = "";
                    if (cve.TryGetProperty("metrics", out var metrics) &&
                        metrics.TryGetProperty("cvssMetricV31", out var metricsV31))
                    {
                        foreach (var metric in metricsV31.EnumerateArray())
                        {
                            if (metric.TryGetProperty("cvssData", out var cvssData))
                            {
                                if (cvssData.TryGetProperty("baseScore", out var scoreEl))
                                    cvssScore = scoreEl.GetDouble();
                                if (cvssData.TryGetProperty("vectorString", out var vecEl))
                                    cvssVector = vecEl.GetString() ?? "";
                                break;
                            }
                        }
                    }

                    if (cvssScore >= 7.0)
                        results.Add((cveId, cvssScore, cvssVector, description));
                }
                catch { }
            }
        }
        catch { }

        return results;
    }
}

using System.Runtime.Versioning;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Browser;

[SupportedOSPlatform("windows")]
public sealed class BrowserExtensionAuditor : IBrowserExtensionAuditor
{
    private static readonly HashSet<string> KnownGoodExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "nmmhkkegccagdldgiimedpiccmgmieda",
        "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
        "aapocclcgogkmnckokdopfmhonfmgoek",
        "pkedcjkdefgpdelpbcmbmeomcjbeemfm",
        "nofbmhihoohajnmfkkbimiaoffdmhiig"
    };

    public async Task<IReadOnlyList<BrowserExtensionFinding>> AuditAsync(CancellationToken ct = default)
    {
        var results = new List<BrowserExtensionFinding>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var chromePath = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions");
            AuditChromiumExtensions(results, chromePath, "Chrome", now);

            var edgePath = Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Extensions");
            AuditChromiumExtensions(results, edgePath, "Edge", now);

            var firefoxProfilesPath = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            AuditFirefoxExtensions(results, firefoxProfilesPath, now);
        }, ct);

        return results;
    }

    private static void AuditChromiumExtensions(List<BrowserExtensionFinding> results, string extensionsPath, string browser, DateTime now)
    {
        if (!Directory.Exists(extensionsPath)) return;

        foreach (var extensionDir in Directory.EnumerateDirectories(extensionsPath))
        {
            try
            {
                var extensionId = Path.GetFileName(extensionDir);
                if (string.IsNullOrEmpty(extensionId)) continue;

                var versionDirs = Directory.GetDirectories(extensionDir);
                if (versionDirs.Length == 0) continue;

                Array.Sort(versionDirs);
                var latestVersionDir = versionDirs[^1];
                var manifestPath = Path.Combine(latestVersionDir, "manifest.json");
                if (!File.Exists(manifestPath)) continue;

                var manifestContent = File.ReadAllText(manifestPath);
                using var doc = JsonDocument.Parse(manifestContent);
                var root = doc.RootElement;

                var name = root.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? extensionId : extensionId;
                var version = root.TryGetProperty("version", out var versionProp) ? versionProp.GetString() ?? "unknown" : "unknown";

                var permissions = ExtractPermissions(root);
                var (isSuspicious, riskReason, severity) = EvaluateChromiumPermissions(extensionId, name, permissions);

                results.Add(new BrowserExtensionFinding
                {
                    Id = Guid.NewGuid(),
                    Browser = browser,
                    ExtensionId = extensionId,
                    ExtensionName = name,
                    Version = version,
                    Permissions = string.Join(", ", permissions),
                    IsSuspicious = isSuspicious,
                    RiskReason = riskReason,
                    Severity = severity,
                    AuditedAtUtc = now
                });
            }
            catch { }
        }
    }

    private static void AuditFirefoxExtensions(List<BrowserExtensionFinding> results, string profilesPath, DateTime now)
    {
        if (!Directory.Exists(profilesPath)) return;

        foreach (var profileDir in Directory.EnumerateDirectories(profilesPath))
        {
            try
            {
                var extensionsJsonPath = Path.Combine(profileDir, "extensions.json");
                if (!File.Exists(extensionsJsonPath)) continue;

                var content = File.ReadAllText(extensionsJsonPath);
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;

                if (!root.TryGetProperty("addons", out var addons)) continue;

                foreach (var addon in addons.EnumerateArray())
                {
                    try
                    {
                        var id = addon.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "unknown" : "unknown";
                        var name = addon.TryGetProperty("defaultLocale", out var localeProp) &&
                                   localeProp.TryGetProperty("name", out var lnProp)
                            ? lnProp.GetString() ?? id : id;
                        var version = addon.TryGetProperty("version", out var vProp) ? vProp.GetString() ?? "unknown" : "unknown";

                        var permissions = new List<string>();
                        if (addon.TryGetProperty("userPermissions", out var userPerms) &&
                            userPerms.TryGetProperty("permissions", out var permsArr))
                        {
                            foreach (var p in permsArr.EnumerateArray())
                            {
                                var pStr = p.GetString();
                                if (!string.IsNullOrEmpty(pStr)) permissions.Add(pStr);
                            }
                        }

                        var (isSuspicious, riskReason, severity) = EvaluateFirefoxPermissions(id, name, permissions);

                        results.Add(new BrowserExtensionFinding
                        {
                            Id = Guid.NewGuid(),
                            Browser = "Firefox",
                            ExtensionId = id,
                            ExtensionName = name,
                            Version = version,
                            Permissions = string.Join(", ", permissions),
                            IsSuspicious = isSuspicious,
                            RiskReason = riskReason,
                            Severity = severity,
                            AuditedAtUtc = now
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static List<string> ExtractPermissions(JsonElement root)
    {
        var permissions = new List<string>();
        if (root.TryGetProperty("permissions", out var permsArr))
        {
            foreach (var p in permsArr.EnumerateArray())
            {
                var pStr = p.GetString();
                if (!string.IsNullOrEmpty(pStr)) permissions.Add(pStr);
            }
        }
        if (root.TryGetProperty("host_permissions", out var hostPerms))
        {
            foreach (var p in hostPerms.EnumerateArray())
            {
                var pStr = p.GetString();
                if (!string.IsNullOrEmpty(pStr)) permissions.Add(pStr);
            }
        }
        return permissions;
    }

    private static (bool IsSuspicious, string RiskReason, int Severity) EvaluateChromiumPermissions(
        string extensionId, string name, List<string> permissions)
    {
        if (KnownGoodExtensions.Contains(extensionId))
            return (false, string.Empty, 1);

        var hasAllUrls = permissions.Any(p => p == "<all_urls>" || p == "http://*/*" || p == "https://*/*" || p == "*://*/*");
        var hasClipboardRead = permissions.Contains("clipboardRead");
        var hasWebRequest = permissions.Contains("webRequest");
        var hasCookies = permissions.Contains("cookies");
        var lowerName = name.ToLowerInvariant();

        if (hasAllUrls && hasClipboardRead)
            return (true, "Access to all URLs + clipboard read — potential credential harvester", 8);

        if (hasAllUrls && hasCookies)
            return (true, "Access to all URLs + cookies — potential session hijacker", 7);

        if (lowerName.Contains("toolbar") || lowerName.Contains("search") && lowerName.Contains("helper"))
            return (true, $"Extension name suggests toolbar/search hijacker: '{name}'", 6);

        if (hasAllUrls && hasWebRequest)
            return (true, "Access to all URLs with webRequest — potentially intercepts all traffic", 5);

        return (false, string.Empty, 1);
    }

    private static (bool IsSuspicious, string RiskReason, int Severity) EvaluateFirefoxPermissions(
        string extensionId, string name, List<string> permissions)
    {
        var hasAllUrls = permissions.Any(p => p == "<all_urls>" || p == "http://*/*" || p == "https://*/*");
        var hasClipboardRead = permissions.Contains("clipboardRead");
        var hasCookies = permissions.Contains("cookies");
        var lowerName = name.ToLowerInvariant();

        if (hasAllUrls && hasClipboardRead)
            return (true, "Access to all URLs + clipboard read — potential credential harvester", 8);

        if (hasAllUrls && hasCookies)
            return (true, "Access to all URLs + cookies — potential session hijacker", 7);

        if (lowerName.Contains("toolbar") || lowerName.Contains("search helper"))
            return (true, $"Extension name suggests toolbar/search hijacker: '{name}'", 6);

        return (false, string.Empty, 1);
    }
}

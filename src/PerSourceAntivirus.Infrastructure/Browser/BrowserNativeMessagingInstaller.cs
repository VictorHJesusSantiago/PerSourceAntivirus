using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

namespace PerSourceAntivirus.Infrastructure.Browser;

[SupportedOSPlatform("windows")]
public sealed class BrowserNativeMessagingInstaller
{
    private const string HostName = "com.persourceantivirus.browserprotection";

    public void Install(string executablePath)
    {
        var manifest = new
        {
            name = HostName,
            description = "PerSourceAntivirus native messaging host for browser protection",
            path = executablePath,
            type = "stdio",
            allowed_origins = new[]
            {
                "chrome-extension://",
                "edge-extension://"
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        var manifestDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PerSourceAntivirus", "NativeMessaging");
        Directory.CreateDirectory(manifestDir);

        var manifestPath = Path.Combine(manifestDir, $"{HostName}.json");
        File.WriteAllText(manifestPath, manifestJson);

        RegisterForChrome(manifestPath);
        RegisterForEdge(manifestPath);
    }

    public void Uninstall()
    {
        try
        {
            using var chromeKey = Registry.CurrentUser.OpenSubKey(
                $@"Software\Google\Chrome\NativeMessagingHosts", writable: true);
            chromeKey?.DeleteSubKeyTree(HostName, throwOnMissingSubKey: false);
        }
        catch { }

        try
        {
            using var edgeKey = Registry.CurrentUser.OpenSubKey(
                $@"Software\Microsoft\Edge\NativeMessagingHosts", writable: true);
            edgeKey?.DeleteSubKeyTree(HostName, throwOnMissingSubKey: false);
        }
        catch { }
    }

    private static void RegisterForChrome(string manifestPath)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                $@"Software\Google\Chrome\NativeMessagingHosts\{HostName}");
            key.SetValue(null, manifestPath);
        }
        catch { }
    }

    private static void RegisterForEdge(string manifestPath)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(
                $@"Software\Microsoft\Edge\NativeMessagingHosts\{HostName}");
            key.SetValue(null, manifestPath);
        }
        catch { }
    }
}

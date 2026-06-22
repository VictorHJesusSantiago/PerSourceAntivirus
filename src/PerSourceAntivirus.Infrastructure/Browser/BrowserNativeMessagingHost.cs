using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Browser;

[SupportedOSPlatform("windows")]
public sealed class BrowserNativeMessagingHost(IDomainBlocklist domainBlocklist)
{
    public async Task RunAsync(CancellationToken ct)
    {
        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();

        while (!ct.IsCancellationRequested)
        {
            var message = await ReadMessageAsync(stdin, ct);
            if (message == null) break;

            var response = ProcessMessage(message);
            await WriteMessageAsync(stdout, response, ct);
        }
    }

    private static async Task<JsonDocument?> ReadMessageAsync(Stream stdin, CancellationToken ct)
    {
        try
        {
            var lengthBytes = new byte[4];
            var bytesRead = 0;
            while (bytesRead < 4)
            {
                var read = await stdin.ReadAsync(lengthBytes.AsMemory(bytesRead, 4 - bytesRead), ct);
                if (read == 0) return null;
                bytesRead += read;
            }

            var length = BitConverter.ToInt32(lengthBytes, 0);
            if (length <= 0 || length > 1024 * 1024) return null;

            var jsonBytes = new byte[length];
            bytesRead = 0;
            while (bytesRead < length)
            {
                var read = await stdin.ReadAsync(jsonBytes.AsMemory(bytesRead, length - bytesRead), ct);
                if (read == 0) return null;
                bytesRead += read;
            }

            return JsonDocument.Parse(jsonBytes);
        }
        catch (OperationCanceledException) { return null; }
        catch { return null; }
    }

    private static async Task WriteMessageAsync(Stream stdout, object response, CancellationToken ct)
    {
        try
        {
            var json = JsonSerializer.Serialize(response);
            var jsonBytes = Encoding.UTF8.GetBytes(json);
            var lengthBytes = BitConverter.GetBytes(jsonBytes.Length);
            await stdout.WriteAsync(lengthBytes, ct);
            await stdout.WriteAsync(jsonBytes, ct);
            await stdout.FlushAsync(ct);
        }
        catch { }
    }

    private object ProcessMessage(JsonDocument message)
    {
        try
        {
            var root = message.RootElement;
            if (!root.TryGetProperty("action", out var actionProp))
                return new { error = "Missing action" };

            var action = actionProp.GetString();

            if (action == "checkUrl")
            {
                if (!root.TryGetProperty("url", out var urlProp))
                    return new { blocked = false, reason = string.Empty };

                var url = urlProp.GetString() ?? string.Empty;
                return CheckUrl(url);
            }

            if (action == "ping")
                return new { pong = true, version = "1.0.0" };

            return new { error = $"Unknown action: {action}" };
        }
        catch
        {
            return new { error = "Failed to process message" };
        }
    }

    private object CheckUrl(string url)
    {
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return new { blocked = false, reason = string.Empty };

            var host = uri.Host;

            if (domainBlocklist.IsSuspiciousDomain(host, out var reason))
                return new { blocked = true, reason = reason ?? "Malicious domain" };

            return new { blocked = false, reason = string.Empty };
        }
        catch
        {
            return new { blocked = false, reason = string.Empty };
        }
    }
}

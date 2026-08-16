using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Siem;

public class SyslogCefExporter : ISiemExporter
{
    public const string HttpClientName = "psav-siem";

    public SiemProtocol Protocol { get; }
    public string Host { get; }
    public int Port { get; }
    public string? ApiKey { get; }

    private readonly IHttpClientFactory? _httpClientFactory;

    public SyslogCefExporter(
        SiemProtocol protocol = SiemProtocol.Disabled,
        string host = "127.0.0.1",
        int port = -1,
        string? apiKey = null,
        IHttpClientFactory? httpClientFactory = null)
    {
        Protocol = protocol;
        Host = host;
        ApiKey = apiKey;
        _httpClientFactory = httpClientFactory;

        if (port < 0)
            Port = protocol == SiemProtocol.HttpJson ? 9200 : 514;
        else
            Port = port;
    }

    public bool IsEnabled => Protocol != SiemProtocol.Disabled;

    public async Task ExportAsync(SiemEventPayload evt, CancellationToken ct = default)
    {
        if (!IsEnabled) return;

        switch (Protocol)
        {
            case SiemProtocol.SyslogUdp:
                await SendSyslogUdpAsync(evt, ct);
                break;
            case SiemProtocol.SyslogTcp:
                await SendSyslogTcpAsync(evt, ct);
                break;
            case SiemProtocol.HttpJson:
                await SendHttpJsonAsync(evt, ct);
                break;
        }
    }

    public async Task ExportBatchAsync(IEnumerable<SiemEventPayload> events, CancellationToken ct = default)
    {
        if (!IsEnabled) return;

        foreach (var evt in events)
        {
            ct.ThrowIfCancellationRequested();
            await ExportAsync(evt, ct);
        }
    }

    private static string BuildCefMessage(SiemEventPayload evt)
    {
        var timestamp = evt.OccurredAtUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var extParts = new List<string>();

        extParts.Add($"rt={timestamp}");

        if (!string.IsNullOrEmpty(evt.SourceIp))
            extParts.Add($"src={evt.SourceIp}");

        if (!string.IsNullOrEmpty(evt.DestinationIp))
            extParts.Add($"dst={evt.DestinationIp}");

        if (!string.IsNullOrEmpty(evt.FileName))
            extParts.Add($"fname={evt.FileName}");

        if (!string.IsNullOrEmpty(evt.UserName))
            extParts.Add($"suser={evt.UserName}");

        if (evt.Extensions != null)
        {
            foreach (var (key, value) in evt.Extensions)
            {
                var safeKey = key.Replace(" ", "_");
                var safeVal = value.Replace("\\", "\\\\").Replace("=", "\\=");
                extParts.Add($"{safeKey}={safeVal}");
            }
        }

        var extensions = string.Join(" ", extParts);

        return $"CEF:0|{EscapeCefHeader(evt.DeviceVendor)}|{EscapeCefHeader(evt.DeviceProduct)}|{EscapeCefHeader(evt.DeviceVersion)}|{evt.SignatureId}|{EscapeCefHeader(evt.Name)}|{evt.Severity}|{extensions}";
    }

    private static string EscapeCefHeader(string value)
        => value.Replace("\\", "\\\\").Replace("|", "\\|");

    private static string WrapInSyslog(string cefMessage)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var hostname = Dns.GetHostName();
        var pid = Environment.ProcessId;
        return $"<134>1 {timestamp} {hostname} PSAV {pid} - - {cefMessage}";
    }

    private async Task SendSyslogUdpAsync(SiemEventPayload evt, CancellationToken ct)
    {
        var cef = BuildCefMessage(evt);
        var syslogMsg = WrapInSyslog(cef);
        var bytes = Encoding.UTF8.GetBytes(syslogMsg);

        using var udp = new UdpClient();
        await udp.SendAsync(bytes, bytes.Length, Host, Port).WaitAsync(ct);
    }

    private async Task SendSyslogTcpAsync(SiemEventPayload evt, CancellationToken ct)
    {
        var cef = BuildCefMessage(evt);
        var syslogMsg = WrapInSyslog(cef);
        var bytes = Encoding.UTF8.GetBytes(syslogMsg + "\n");

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(Host, Port, ct);
        await using var stream = tcp.GetStream();
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
    }

    private async Task SendHttpJsonAsync(SiemEventPayload evt, CancellationToken ct)
    {
        if (_httpClientFactory is null) return;

        var doc = new Dictionary<string, object?>
        {
            ["@timestamp"] = evt.OccurredAtUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            ["severity"] = evt.Severity,
            ["name"] = evt.Name,
            ["deviceVendor"] = evt.DeviceVendor,
            ["deviceProduct"] = evt.DeviceProduct,
            ["deviceVersion"] = evt.DeviceVersion,
            ["signatureId"] = evt.SignatureId,
            ["src"] = evt.SourceIp,
            ["dst"] = evt.DestinationIp,
            ["fileName"] = evt.FileName,
            ["userName"] = evt.UserName
        };

        if (evt.Extensions != null)
        {
            foreach (var (key, value) in evt.Extensions)
                doc[key] = value;
        }

        var json = JsonSerializer.Serialize(doc);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            using var http = _httpClientFactory.CreateClient(HttpClientName);
            using var request = new HttpRequestMessage(
                HttpMethod.Post, $"http://{Host}:{Port}/psav-events/_doc") { Content = content };
            if (!string.IsNullOrEmpty(ApiKey))
                request.Headers.TryAddWithoutValidation("Authorization", $"ApiKey {ApiKey}");

            await http.SendAsync(request, ct);
        }
        catch (HttpRequestException)
        {
        }
    }
}

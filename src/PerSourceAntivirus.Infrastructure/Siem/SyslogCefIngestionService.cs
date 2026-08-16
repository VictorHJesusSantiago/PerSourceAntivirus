using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Siem;

public sealed class SyslogCefIngestionService(IServiceScopeFactory scopeFactory) : ISyslogCefIngestionService, IDisposable
{
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    public event EventHandler<RemoteAgentEventArgs>? EventReceived;

    public Task StartAsync(int port, CancellationToken ct = default)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _udpClient = new UdpClient(port);
        _loopTask = Task.Run(() => ReceiveLoopAsync(_cts.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _udpClient?.Close(); } catch { }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _udpClient is not null)
        {
            UdpReceiveResult result;
            try { result = await _udpClient.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (Exception) { break; }

            try
            {
                var message = Encoding.UTF8.GetString(result.Buffer);
                var evt = ParseCefMessage(message, result.RemoteEndPoint.Address.ToString());
                if (evt is null) continue;

                await PersistAsync(evt, ct).ConfigureAwait(false);
                EventReceived?.Invoke(this, new RemoteAgentEventArgs(evt));
            }
            catch { }
        }
    }

    private async Task PersistAsync(RemoteAgentEvent evt, CancellationToken ct)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IRemoteAgentEventRepository>();
            await repository.AddAsync(evt, ct).ConfigureAwait(false);
        }
        catch { }
    }

    internal static RemoteAgentEvent? ParseCefMessage(string raw, string sourceHost)
    {
        var cefIndex = raw.IndexOf("CEF:0|", StringComparison.Ordinal);
        if (cefIndex < 0) return null;

        var cef = raw[cefIndex..];
        var parts = SplitUnescaped(cef, '|');
        if (parts.Count < 8) return null;

        var extensions = new Dictionary<string, string>();
        foreach (var token in parts[7].Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = token.IndexOf('=');
            if (eq <= 0) continue;
            extensions[token[..eq]] = token[(eq + 1)..];
        }

        int.TryParse(parts[6], out var severity);

        return new RemoteAgentEvent
        {
            Id = Guid.NewGuid(),
            SourceHost = sourceHost,
            DeviceVendor = parts[1],
            DeviceProduct = parts[2],
            SignatureId = parts[4],
            Name = parts[5],
            Severity = severity,
            ExtensionsJson = JsonSerializer.Serialize(extensions),
            ReceivedAtUtc = DateTime.UtcNow
        };
    }

    private static List<string> SplitUnescaped(string s, char separator)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length) { current.Append(s[i + 1]); i++; continue; }
            if (s[i] == separator) { result.Add(current.ToString()); current.Clear(); continue; }
            current.Append(s[i]);
        }
        result.Add(current.ToString());
        return result;
    }

    public void Dispose()
    {
        Stop();
        _udpClient?.Dispose();
    }
}

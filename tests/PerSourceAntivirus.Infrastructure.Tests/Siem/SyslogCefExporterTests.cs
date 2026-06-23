using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Siem;

namespace PerSourceAntivirus.Infrastructure.Tests.Siem;

public class SyslogCefExporterTests
{
    [Fact]
    public void IsEnabled_ReturnsFalse_WhenDisabled()
    {
        new SyslogCefExporter(SiemProtocol.Disabled).IsEnabled.Should().BeFalse();
    }

    [Fact]
    public void IsEnabled_ReturnsTrue_WhenSyslogUdp()
    {
        new SyslogCefExporter(SiemProtocol.SyslogUdp, "127.0.0.1", 9999).IsEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task ExportBatchAsync_DoesNothing_WhenDisabled()
    {
        using var exporter = new SyslogCefExporter(SiemProtocol.Disabled);
        var events = Enumerable.Range(0, 3).Select(i =>
            new SiemEventPayload("PSAV", "Test", "1.0", i, $"Event{i}", 3, DateTime.UtcNow, null, null, null, null, null));

        var act = async () => await exporter.ExportBatchAsync(events);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ExportAsync_SendsUdpPacket_WhenSyslogUdp()
    {
        using var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
        using var exporter = new SyslogCefExporter(SiemProtocol.SyslogUdp, "127.0.0.1", port);
        var evt = new SiemEventPayload("PSAV", "Test", "1.0", 1001, "TestEvent", 5, DateTime.UtcNow, null, null, null, null, null);

        var receiveTask = listener.ReceiveAsync();
        await exporter.ExportAsync(evt);
        var received = await receiveTask.WaitAsync(TimeSpan.FromSeconds(5));
        var message = System.Text.Encoding.UTF8.GetString(received.Buffer);

        message.Should().Contain("CEF:0");
        message.Should().Contain("TestEvent");
    }
}

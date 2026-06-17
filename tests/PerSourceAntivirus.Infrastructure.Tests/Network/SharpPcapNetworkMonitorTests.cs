using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Network;

namespace PerSourceAntivirus.Infrastructure.Tests.Network;

public class SharpPcapNetworkMonitorTests
{
    [Fact]
    public void GetAvailableDevices_DoesNotThrow_WhenNpcapIsNotInstalled()
    {
        var monitor = new SharpPcapNetworkMonitor();

        var action = () => monitor.GetAvailableDevices();

        action.Should().NotThrow();
    }

    [Fact]
    public void GetAvailableDevices_ReturnsReadOnlyList()
    {
        var monitor = new SharpPcapNetworkMonitor();

        var devices = monitor.GetAvailableDevices();

        devices.Should().NotBeNull();
    }
}

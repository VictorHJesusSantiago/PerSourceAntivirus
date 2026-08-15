using MediatR;
using PerSourceAntivirus.Application.Network.Queries.ListCaptureDevices;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class DevicesCommand(IMediator mediator) : ICliCommand
{
    public string Name => "devices";
    public string Usage => "devices";
    public string Description => "List available network capture devices";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var devices = await mediator.Send(new ListCaptureDevicesQuery(), ct);
        if (devices.Count == 0)
        {
            Console.WriteLine("No capture devices found.");
            Console.WriteLine("Install Npcap (https://npcap.com/) to enable network monitoring.");
            return 0;
        }

        Console.WriteLine($"{"Name",-40} Description");
        Console.WriteLine(new string('-', 100));
        foreach (var device in devices)
            Console.WriteLine($"{device.Name,-40} {device.Description}");

        return 0;
    }
}

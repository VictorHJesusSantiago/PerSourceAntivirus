using MediatR;
using PerSourceAntivirus.Application.Network.Commands.StartDnsMonitor;
using PerSourceAntivirus.Application.Network.Commands.StartNetworkCapture;
using PerSourceAntivirus.Application.Network.Queries.GetDnsEvents;
using PerSourceAntivirus.Application.Network.Queries.GetNetworkConnectionEvents;
using PerSourceAntivirus.Application.Process.Commands.StartProcessMonitor;
using PerSourceAntivirus.Application.Process.Queries.GetProcessEvents;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class MonitorCommand(IMediator mediator) : ICliCommand
{
    public string Name => "monitor";
    public string Usage => "monitor [--seconds N] [--device D]";
    public string Description => "Capture network traffic (default: 30s)";

    public Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var seconds = CommandArgs.GetIntOption(args, "--seconds", 30);
        var device = CommandArgs.GetOption(args, "--device");

        return CommandArgs.RunCancellableAsync(
            $"Capturing network traffic for {seconds}s... (Ctrl+C to stop early)",
            "Monitoring stopped.",
            async token =>
            {
                var result = await mediator.Send(new StartNetworkCaptureCommand(device, seconds), token);
                Console.WriteLine($"Captured {result.PacketsCaptured} packet(s) in {result.Duration.TotalSeconds:F1}s. Blocklisted: {result.BlocklistedCount}");
            },
            ct);
    }
}

public sealed class ConnectionsCommand(IMediator mediator) : ICliCommand
{
    public string Name => "connections";
    public string Usage => "connections [--blocklisted]";
    public string Description => "List captured network connection events";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var onlyBlocklisted = CommandArgs.HasFlag(args, "--blocklisted");
        var events = await mediator.Send(new GetNetworkConnectionEventsQuery(onlyBlocklisted), ct);

        if (events.Count == 0)
        {
            Console.WriteLine(onlyBlocklisted ? "No blocklisted connections recorded." : "No captured connections. Run: monitor");
            return 0;
        }

        Console.WriteLine($"{"Time",-22} {"Proto",-6} {"Source",-25} {"Destination",-25} {"Bytes",-8} Blocked");
        Console.WriteLine(new string('-', 110));
        foreach (var ev in events)
        {
            var src = $"{ev.SourceAddress}:{ev.SourcePort}";
            var dst = $"{ev.DestinationAddress}:{ev.DestinationPort}";
            Console.WriteLine($"{ev.CapturedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.Protocol,-6} {src,-25} {dst,-25} {ev.PacketLength,-8} {(ev.IsBlocklisted ? "YES" : "")}");
        }
        return 0;
    }
}

public sealed class DnsMonitorCommand(IMediator mediator) : ICliCommand
{
    public string Name => "dns-monitor";
    public string Usage => "dns-monitor [--seconds N] [--device D]";
    public string Description => "Capture DNS queries (default: 30s)";

    public Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var seconds = CommandArgs.GetIntOption(args, "--seconds", 30);
        var device = CommandArgs.GetOption(args, "--device");

        return CommandArgs.RunCancellableAsync(
            $"Capturing DNS queries for {seconds}s... (Ctrl+C to stop early)",
            "DNS monitoring stopped.",
            async token =>
            {
                var result = await mediator.Send(new StartDnsMonitorCommand(device, seconds), token);
                Console.WriteLine($"Captured {result.QueriesCaptured} DNS query(s) in {result.Duration.TotalSeconds:F1}s. Suspicious: {result.SuspiciousCount}");
            },
            ct);
    }
}

public sealed class DnsEventsCommand(IMediator mediator) : ICliCommand
{
    public string Name => "dns-events";
    public string Usage => "dns-events [--suspicious]";
    public string Description => "List captured DNS query events";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var onlySuspicious = CommandArgs.HasFlag(args, "--suspicious");
        var events = await mediator.Send(new GetDnsEventsQuery(onlySuspicious), ct);

        if (events.Count == 0)
        {
            Console.WriteLine(onlySuspicious ? "No suspicious DNS queries recorded." : "No DNS events. Run: dns-monitor");
            return 0;
        }

        Console.WriteLine($"{"Time",-22} {"Type",-6} {"Source",-20} {"Suspicious",-10} Domain");
        Console.WriteLine(new string('-', 110));
        foreach (var ev in events)
            Console.WriteLine($"{ev.CapturedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.QueryType,-6} {ev.SourceAddress,-20} {(ev.IsSuspicious ? "YES" : ""),-10} {ev.QueryName}");

        return 0;
    }
}

public sealed class ProcessMonitorCommand(IMediator mediator) : ICliCommand
{
    public string Name => "process-monitor";
    public string Usage => "process-monitor [--seconds N]";
    public string Description => "Monitor process creation via WMI (default: 30s)";

    public Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var seconds = CommandArgs.GetIntOption(args, "--seconds", 30);

        return CommandArgs.RunCancellableAsync(
            $"Monitoring process creation for {seconds}s... (Ctrl+C to stop early)",
            "Process monitoring stopped.",
            async token =>
            {
                var result = await mediator.Send(new StartProcessMonitorCommand(seconds), token);
                Console.WriteLine($"Recorded {result.EventsRecorded} process event(s) in {result.Duration.TotalSeconds:F1}s. Suspicious: {result.SuspiciousCount}");
            },
            ct);
    }
}

public sealed class ProcessEventsCommand(IMediator mediator) : ICliCommand
{
    public string Name => "process-events";
    public string Usage => "process-events [--suspicious]";
    public string Description => "List captured process creation events";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var onlySuspicious = CommandArgs.HasFlag(args, "--suspicious");
        var events = await mediator.Send(new GetProcessEventsQuery(onlySuspicious), ct);

        if (events.Count == 0)
        {
            Console.WriteLine(onlySuspicious ? "No suspicious process events recorded." : "No process events. Run: process-monitor");
            return 0;
        }

        Console.WriteLine($"{"Time",-22} {"PID",-7} {"Process",-25} {"Parent",-25} Suspicious");
        Console.WriteLine(new string('-', 110));
        foreach (var ev in events)
            Console.WriteLine($"{ev.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {ev.ProcessId,-7} {ev.ProcessName,-25} {ev.ParentProcessName,-25} {(ev.IsSuspicious ? $"YES - {ev.SuspicionReason}" : "")}");

        return 0;
    }
}

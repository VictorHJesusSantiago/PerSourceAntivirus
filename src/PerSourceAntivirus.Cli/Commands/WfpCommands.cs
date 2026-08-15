using MediatR;
using PerSourceAntivirus.Application.Network.Commands.AddWfpBlock;
using PerSourceAntivirus.Application.Network.Commands.RemoveWfpBlock;
using PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;
using PerSourceAntivirus.Application.Network.Queries.GetWfpBlocks;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class WfpListCommand(IMediator mediator) : ICliCommand
{
    public string Name => "wfp-list";
    public string Usage => "wfp-list";
    public string Description => "List active WFP firewall blocks";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var blocks = await mediator.Send(new GetWfpBlocksQuery(), ct);
        if (blocks.Count == 0)
        {
            Console.WriteLine("No active WFP blocks. Run: wfp-block <ip>");
            return 0;
        }

        Console.WriteLine($"{"IP Address",-20} {"Outbound ID",-14} {"Inbound ID",-14} Reason");
        Console.WriteLine(new string('-', 80));
        foreach (var b in blocks)
            Console.WriteLine($"{b.IpAddress,-20} {b.FilterIdOutboundV4,-14} {b.FilterIdInboundV4,-14} {b.Reason}");

        return 0;
    }
}

public sealed class WfpSyncCommand(IMediator mediator) : ICliCommand
{
    public string Name => "wfp-sync";
    public string Usage => "wfp-sync";
    public string Description => "Sync the IP blocklist into WFP filters";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Syncing IP blocklist to WFP...");
        var result = await mediator.Send(new SyncWfpBlocklistCommand(), ct);
        Console.WriteLine($"Added: {result.Added}  Already blocked: {result.AlreadyBlocked}  Errors: {result.Errors}");
        return 0;
    }
}

public sealed class WfpBlockCommand(IMediator mediator) : ICliCommand
{
    public string Name => "wfp-block";
    public string Usage => "wfp-block <ip> [--reason R]";
    public string Description => "Block an IPv4 address at the WFP layer (requires admin)";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: wfp-block <ip> [--reason <text>]");
            return 1;
        }

        var ip = args[1];
        var reason = "manual";
        for (var i = 2; i < args.Length; i++)
            if (args[i] == "--reason" && i + 1 < args.Length) { reason = args[++i]; }

        Console.WriteLine($"Adding WFP block for {ip}...");
        var result = await mediator.Send(new AddWfpBlockCommand(ip, reason), ct);
        if (!result.Success)
        {
            Console.Error.WriteLine($"Error: {result.ErrorMessage}");
            return 1;
        }

        Console.WriteLine($"Blocked: {ip}");
        Console.WriteLine($"  Outbound filter ID: {result.FilterIdOutboundV4}");
        Console.WriteLine($"  Inbound  filter ID: {result.FilterIdInboundV4}");
        return 0;
    }
}

public sealed class WfpUnblockCommand(IMediator mediator) : ICliCommand
{
    public string Name => "wfp-unblock";
    public string Usage => "wfp-unblock <ip>";
    public string Description => "Remove a WFP block for an IPv4 address";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: wfp-unblock <ip>");
            return 1;
        }

        var removed = await mediator.Send(new RemoveWfpBlockCommand(args[1]), ct);
        Console.WriteLine(removed ? $"Removed WFP block for {args[1]}." : $"No active block found for {args[1]}.");
        return 0;
    }
}

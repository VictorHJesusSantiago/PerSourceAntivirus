using MediatR;
using PerSourceAntivirus.Application.Scans.Commands.QuarantineFile;
using PerSourceAntivirus.Application.Scans.Commands.RestoreFile;
using PerSourceAntivirus.Application.Scans.Commands.WatchDirectory;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class QuarantineCommand(IMediator mediator) : ICliCommand
{
    public string Name => "quarantine";
    public string Usage => "quarantine <file-id>";
    public string Description => "Move a scanned file to the quarantine directory";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args.Length < 2 || !Guid.TryParse(args[1], out var fileId))
        {
            Console.Error.WriteLine($"Usage: {Usage}");
            return 1;
        }

        try
        {
            var result = await mediator.Send(new QuarantineFileCommand(fileId), ct);
            Console.WriteLine($"Quarantined: {result.OriginalPath}");
            Console.WriteLine($"Stored at:   {result.QuarantinePath}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }
}

public sealed class RestoreCommand(IMediator mediator) : ICliCommand
{
    public string Name => "restore";
    public string Usage => "restore <file-id>";
    public string Description => "Restore a quarantined file to its original path";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args.Length < 2 || !Guid.TryParse(args[1], out var fileId))
        {
            Console.Error.WriteLine($"Usage: {Usage}");
            return 1;
        }

        try
        {
            var result = await mediator.Send(new RestoreFileCommand(fileId), ct);
            Console.WriteLine($"Restored to: {result.RestoredPath}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }
}

public sealed class WatchCommand(IMediator mediator) : ICliCommand
{
    public string Name => "watch";
    public string Usage => "watch <path>";
    public string Description => "Watch a directory and scan new/modified files";

    public Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine($"Usage: {Usage}");
            return Task.FromResult(1);
        }

        return CommandArgs.RunCancellableAsync(
            $"Watching {args[1]} for new/modified files... (Ctrl+C to stop)",
            "Watch stopped.",
            async token =>
            {
                var result = await mediator.Send(new WatchDirectoryCommand(args[1]), token);
                Console.WriteLine($"Watch stopped. Scanned {result.FilesScanned} file(s), {result.ThreatsDetected} threat(s) detected.");
            },
            ct);
    }
}

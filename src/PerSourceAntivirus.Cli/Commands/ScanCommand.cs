using MediatR;
using PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class ScanCommand(IMediator mediator) : ICliCommand
{
    public string Name => "scan";
    public string Usage => "scan <path>";
    public string Description => "Scan a directory recursively and store results";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine($"Usage: {Usage}");
            return 1;
        }

        var result = await mediator.Send(new ScanDirectoryCommand(args[1]), ct);
        Console.WriteLine($"Scanned {result.FilesScanned} file(s) in {result.Duration.TotalSeconds:F2}s.");
        return 0;
    }
}

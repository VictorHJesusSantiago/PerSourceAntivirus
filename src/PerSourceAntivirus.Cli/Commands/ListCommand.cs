using MediatR;
using PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class ListCommand(IMediator mediator) : ICliCommand
{
    public string Name => "list";
    public string Usage => "list [--format table|json|csv] [--output FILE]";
    public string Description => "List scanned files (default: table)";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var files = await mediator.Send(new GetScannedFilesQuery(), ct);
        if (files.Count == 0)
        {
            Console.WriteLine("No scanned files. Run: scan <path>");
            return 0;
        }

        var format = CommandArgs.GetOption(args, "--format") ?? "table";
        var outputFile = CommandArgs.GetOption(args, "--output");
        var output = ScannedFileFormatter.Format(files, format);

        if (outputFile is not null)
        {
            await File.WriteAllTextAsync(outputFile, output, ct);
            Console.WriteLine($"Exported {files.Count} record(s) to {outputFile}");
        }
        else
        {
            Console.WriteLine(output);
        }

        return 0;
    }
}

namespace PerSourceAntivirus.Cli.Commands;

public interface ICliCommand
{
    string Name { get; }

    string Usage { get; }

    string Description { get; }

    Task<int> ExecuteAsync(string[] args, CancellationToken ct);
}

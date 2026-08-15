namespace PerSourceAntivirus.Cli.Commands;

public sealed class CliCommandRegistry
{
    private readonly Dictionary<string, ICliCommand> _commands;

    public CliCommandRegistry(IEnumerable<ICliCommand> commands)
    {
        _commands = commands.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
    }

    public bool TryGet(string name, out ICliCommand command) => _commands.TryGetValue(name, out command!);

    public IReadOnlyList<ICliCommand> All => _commands.Values
        .OrderBy(c => c.Name, StringComparer.Ordinal)
        .ToList();

    public string BuildHelpSection()
    {
        if (_commands.Count == 0) return string.Empty;

        var width = All.Max(c => c.Usage.Length);
        var lines = All.Select(c => $"  {c.Usage.PadRight(width)}  {c.Description}");
        return string.Join(Environment.NewLine, lines);
    }
}

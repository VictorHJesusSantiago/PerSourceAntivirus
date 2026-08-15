using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class UpdateBlocklistCommand(IBlocklistUpdater updater) : ICliCommand
{
    public string Name => "update-blocklist";
    public string Usage => "update-blocklist";
    public string Description => "Fetch the latest IP blocklist from the configured threat feed";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Fetching updated IP blocklist...");
        var result = await updater.UpdateAsync(ct);

        if (!result.Success)
        {
            Console.Error.WriteLine($"Update failed: {result.ErrorMessage}");
            return 1;
        }

        Console.WriteLine($"Updated blocklist from {result.Source}: {result.IpsTotal} IP(s) loaded.");
        return 0;
    }
}

public sealed class UpdateYaraRulesCommand(IYaraRulesUpdater updater) : ICliCommand
{
    public string Name => "update-yara-rules";
    public string Usage => "update-yara-rules [--url URL]";
    public string Description => "Download YARA rules and reload the scanner";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Downloading YARA rules...");
        var url = CommandArgs.GetOption(args, "--url");
        var result = await updater.UpdateAsync(url, ct);

        if (!result.Success)
        {
            Console.Error.WriteLine($"Update failed: {result.ErrorMessage}");
            return 1;
        }

        Console.WriteLine($"Downloaded {result.FilesDownloaded} rule file(s) from {result.Source}. Scanner reloaded.");
        return 0;
    }
}

using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class UpdateFeedsCommand(IEnumerable<IThreatFeedUpdater> feedUpdaters) : ICliCommand
{
    public string Name => "update-feeds";
    public string Usage => "update-feeds";
    public string Description => "Download every configured threat intelligence feed";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Updating threat intelligence feeds...");

        var allOk = true;
        foreach (var feed in feedUpdaters)
        {
            Console.Write($"  [{feed.FeedName}] ");
            var result = await feed.UpdateAsync(ct);
            if (result.Success)
            {
                Console.WriteLine($"OK — {result.RecordsAdded} record(s) added, {result.RecordsTotal} total.");
            }
            else
            {
                Console.WriteLine($"FAILED — {result.ErrorMessage}");
                allOk = false;
            }
        }

        return allOk ? 0 : 1;
    }
}

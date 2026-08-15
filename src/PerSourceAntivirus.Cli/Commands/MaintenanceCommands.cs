using MediatR;
using PerSourceAntivirus.Application.SelfIntegrity.Commands.SaveBaseline;
using PerSourceAntivirus.Application.SelfIntegrity.Commands.VerifySelfIntegrity;
using PerSourceAntivirus.Application.Siem.Commands.ExportSiemBatch;
using PerSourceAntivirus.Application.Updates.Commands.ApplyUpdates;
using PerSourceAntivirus.Application.Updates.Commands.CheckUpdates;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class CheckUpdatesCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "check-updates";
    public string Usage => "check-updates";
    public string Description => "Check whether signature/rule updates are available";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Checking for updates...");
        var result = await mediator.Send(new CheckUpdatesCommand(), ct);

        if (!result.UpdateAvailable)
        {
            Console.WriteLine($"Up to date (version {result.CurrentVersion}).");
            return 0;
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"Update available: {result.CurrentVersion} → {result.LatestVersion}");
        Console.ResetColor();
        Console.WriteLine($"Updated components: {string.Join(", ", result.UpdatedComponents)}");
        return 0;
    }
}

public sealed class ApplyUpdatesCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "apply-updates";
    public string Usage => "apply-updates";
    public string Description => "Download and apply all pending updates";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Applying updates...");
        var updated = await mediator.Send(new ApplyUpdatesCommand(), ct);
        Console.WriteLine($"Updated {updated} component(s).");
        return 0;
    }
}

public sealed class VerifyIntegrityCommand(IMediator mediator) : ICliCommand
{
    public string Name => "verify-integrity";
    public string Usage => "verify-integrity";
    public string Description => "Verify PSAV's own binaries against the stored baseline";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Verifying self-integrity of PSAV binaries...");
        var report = await mediator.Send(new VerifySelfIntegrityCommand(), ct);

        if (report.IsIntact)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("INTEGRITY OK — all binaries match baseline.");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("INTEGRITY VIOLATION DETECTED!");
            Console.ResetColor();
            foreach (var f in report.TamperedFiles) Console.WriteLine($"  TAMPERED: {f}");
            foreach (var f in report.MissingFiles) Console.WriteLine($"  MISSING:  {f}");
        }

        Console.WriteLine($"Checked at: {report.CheckedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        return 0;
    }
}

public sealed class SaveBaselineCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "save-baseline";
    public string Usage => "save-baseline";
    public string Description => "Record the current binaries as the integrity baseline";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Saving integrity baseline...");
        var saved = await mediator.Send(new SaveBaselineCommand(), ct);
        Console.WriteLine(saved ? "Baseline saved successfully." : "Failed to save baseline.");
        return saved ? 0 : 1;
    }
}

public sealed class ExportSiemCommand(IMediator mediator) : ICliCommand
{
    public string Name => "export-siem";
    public string Usage => "export-siem [--max N]";
    public string Description => "Export pending alerts to the configured SIEM (default: 100)";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var max = CommandArgs.GetIntOption(args, "--max", 100);
        Console.WriteLine($"Exporting up to {max} SIEM events...");
        var exported = await mediator.Send(new ExportSiemBatchCommand(max), ct);
        Console.WriteLine($"Exported {exported} event(s).");
        return 0;
    }
}

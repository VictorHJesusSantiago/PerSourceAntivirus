using MediatR;
using PerSourceAntivirus.Application.Mbr.Commands.SnapshotMbr;
using PerSourceAntivirus.Application.Mbr.Queries.CheckMbr;
using PerSourceAntivirus.Application.Uefi.Commands.ScanUefi;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class SnapshotMbrCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "snapshot-mbr";
    public string Usage => "snapshot-mbr [--drive N]";
    public string Description => "Hash MBR sector 0 of PhysicalDriveN and store it as the baseline";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var drive = CommandArgs.GetIntOption(args, "--drive", 0);
        Console.WriteLine($"Taking MBR snapshot for PhysicalDrive{drive}...");

        try
        {
            var snap = await mediator.Send(new SnapshotMbrCommand(drive), ct);
            Console.WriteLine($"Snapshot saved: {snap.Id}");
            Console.WriteLine($"  Drive:    PhysicalDrive{snap.DriveIndex}");
            Console.WriteLine($"  SHA-256:  {snap.Sha256Hash}");
            Console.WriteLine($"  Taken at: {snap.TakenAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"  Baseline: {(snap.IsBaseline ? "Yes (first snapshot)" : "No")}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }
}

public sealed class CheckMbrCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "check-mbr";
    public string Usage => "check-mbr [--drive N]";
    public string Description => "Compare the current MBR hash against the stored baseline";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var drive = CommandArgs.GetIntOption(args, "--drive", 0);
        Console.WriteLine($"Checking MBR integrity for PhysicalDrive{drive}...");

        var result = await mediator.Send(new CheckMbrQuery(drive), ct);

        if (result.ErrorMessage is not null)
        {
            Console.Error.WriteLine($"Error reading MBR: {result.ErrorMessage}");
            return 1;
        }

        if (!result.HasBaseline)
        {
            Console.WriteLine("No baseline snapshot found. Run: snapshot-mbr");
            return 0;
        }

        if (result.HashMatched)
        {
            Console.WriteLine("MBR INTACT — hash matches baseline.");
            Console.WriteLine($"  Current:  {result.CurrentHash}");
            Console.WriteLine($"  Baseline: {result.BaselineHash}");
            Console.WriteLine($"  Taken at: {result.BaselineTakenAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            return 0;
        }

        Console.Error.WriteLine("!!! MBR TAMPERED — hash mismatch !!!");
        Console.Error.WriteLine($"  Current:  {result.CurrentHash}");
        Console.Error.WriteLine($"  Baseline: {result.BaselineHash}");
        Console.Error.WriteLine($"  Baseline taken: {result.BaselineTakenAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        return 2;
    }
}

public sealed class ScanUefiCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "scan-uefi";
    public string Usage => "scan-uefi";
    public string Description => "Scan UEFI firmware tables for bootkit signatures";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Scanning UEFI firmware tables for bootkit signatures...");
        var findings = await mediator.Send(new ScanUefiCommand(), ct);
        Console.WriteLine($"Found {findings.Count} UEFI finding(s).");

        if (findings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"{"Time",-22} {"Table",-12} {"Signature",-30} {"Offset",-10} Description");
            Console.WriteLine(new string('-', 130));
            foreach (var u in findings)
                Console.WriteLine($"{u.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {u.TableName,-12} {u.SignatureName,-30} {u.MatchOffset,-10} {u.Description}");
            Console.ResetColor();
        }

        return 0;
    }
}

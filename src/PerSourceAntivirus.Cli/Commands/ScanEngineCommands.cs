using MediatR;
using PerSourceAntivirus.Application.ComHijack.Commands.ScanComHijack;
using PerSourceAntivirus.Application.ComHijack.Queries.GetComAlerts;
using PerSourceAntivirus.Application.Rootkit.Commands.ScanRootkits;
using PerSourceAntivirus.Application.Rootkit.Queries.GetRootkitFindings;
using PerSourceAntivirus.Application.Wmi.Commands.ScanWmiPersistence;
using PerSourceAntivirus.Application.Wmi.Queries.GetWmiAlerts;

namespace PerSourceAntivirus.Cli.Commands;

public sealed class ScanRootkitsCliCommand(IMediator mediator) : ICliCommand
{
    public string Name => "scan-rootkits";
    public string Usage => "scan-rootkits";
    public string Description => "Scan for rootkits (DKOM, hidden drivers, SSDT hooks)";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Scanning for rootkits (DKOM, hidden drivers, SSDT hooks)...");
        var findings = await mediator.Send(new ScanRootkitsCommand(), ct);
        Console.WriteLine($"Found {findings.Count} rootkit indicator(s).");

        if (findings.Count > 0) RootkitFindingPrinter.Print(findings);
        return 0;
    }
}

public sealed class RootkitAlertsCommand(IMediator mediator) : ICliCommand
{
    public string Name => "rootkit-alerts";
    public string Usage => "rootkit-alerts";
    public string Description => "List recorded rootkit findings";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var findings = await mediator.Send(new GetRootkitFindingsQuery(), ct);
        if (findings.Count == 0)
        {
            Console.WriteLine("No rootkit findings recorded. Run: scan-rootkits");
            return 0;
        }

        RootkitFindingPrinter.Print(findings);
        return 0;
    }
}

internal static class RootkitFindingPrinter
{
    public static void Print(IReadOnlyList<PerSourceAntivirus.Domain.Entities.RootkitFinding> findings)
    {
        Console.WriteLine($"{"Time",-22} {"Type",-20} {"Severity",-10} {"PID",-7} Description");
        Console.WriteLine(new string('-', 120));
        foreach (var f in findings)
            Console.WriteLine($"{f.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {f.FindingType,-20} {f.Severity,-10} {f.ProcessId,-7} {f.Description}");
    }
}

public sealed class ScanWmiCommand(IMediator mediator) : ICliCommand
{
    public string Name => "scan-wmi";
    public string Usage => "scan-wmi";
    public string Description => "Scan WMI event subscriptions for persistence";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Scanning WMI event subscriptions for persistence...");
        var findings = await mediator.Send(new ScanWmiPersistenceCommand(), ct);
        Console.WriteLine($"Found {findings.Count} WMI persistence subscription(s).");

        if (findings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            WmiAlertPrinter.Print(findings);
            Console.ResetColor();
        }
        return 0;
    }
}

public sealed class WmiAlertsCommand(IMediator mediator) : ICliCommand
{
    public string Name => "wmi-alerts";
    public string Usage => "wmi-alerts";
    public string Description => "List recorded WMI persistence alerts";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var alerts = await mediator.Send(new GetWmiAlertsQuery(), ct);
        if (alerts.Count == 0)
        {
            Console.WriteLine("No WMI persistence alerts. Run: scan-wmi");
            return 0;
        }

        WmiAlertPrinter.Print(alerts);
        return 0;
    }
}

internal static class WmiAlertPrinter
{
    public static void Print(IReadOnlyList<PerSourceAntivirus.Domain.Entities.WmiPersistenceAlert> alerts)
    {
        Console.WriteLine($"{"Time",-22} {"Severity",-10} {"Consumer",-25} {"Filter",-25} Command/Script");
        Console.WriteLine(new string('-', 140));
        foreach (var w in alerts)
            Console.WriteLine($"{w.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {w.Severity,-10} {w.ConsumerName,-25} {w.FilterName,-25} {w.ScriptOrCommand}");
    }
}

public sealed class ScanComCommand(IMediator mediator) : ICliCommand
{
    public string Name => "scan-com";
    public string Usage => "scan-com";
    public string Description => "Scan for COM hijacking and DLL sideloading";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        Console.WriteLine("Scanning for COM hijacking and DLL sideloading...");
        var alerts = await mediator.Send(new ScanComHijackCommand(), ct);
        Console.WriteLine($"Found {alerts.Count} COM/DLL hijack indicator(s).");

        if (alerts.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            ComAlertPrinter.Print(alerts);
            Console.ResetColor();
        }
        return 0;
    }
}

public sealed class ComAlertsCommand(IMediator mediator) : ICliCommand
{
    public string Name => "com-alerts";
    public string Usage => "com-alerts";
    public string Description => "List recorded COM hijack alerts";

    public async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        var alerts = await mediator.Send(new GetComAlertsQuery(), ct);
        if (alerts.Count == 0)
        {
            Console.WriteLine("No COM hijack alerts. Run: scan-com");
            return 0;
        }

        ComAlertPrinter.Print(alerts);
        return 0;
    }
}

internal static class ComAlertPrinter
{
    public static void Print(IReadOnlyList<PerSourceAntivirus.Domain.Entities.ComHijackAlert> alerts)
    {
        Console.WriteLine($"{"Time",-22} {"Type",-18} {"Severity",-10} {"CLSID/Path",-40} Suspicious Path");
        Console.WriteLine(new string('-', 140));
        foreach (var c in alerts)
            Console.WriteLine($"{c.DetectedAtUtc:yyyy-MM-dd HH:mm:ss,-22} {c.AlertType,-18} {c.Severity,-10} {c.ClsidOrPath,-40} {c.SuspiciousPath}");
    }
}

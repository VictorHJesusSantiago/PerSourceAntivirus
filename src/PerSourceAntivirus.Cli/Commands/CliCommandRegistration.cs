using Microsoft.Extensions.DependencyInjection;

namespace PerSourceAntivirus.Cli.Commands;

public static class CliCommandRegistration
{

    public static IServiceCollection AddCliCommands(this IServiceCollection services)
    {
        services.AddSingleton<ICliCommand, ScanCommand>();
        services.AddSingleton<ICliCommand, DevicesCommand>();
        services.AddSingleton<ICliCommand, UpdateFeedsCommand>();
        services.AddSingleton<ICliCommand, WfpListCommand>();
        services.AddSingleton<ICliCommand, WfpSyncCommand>();
        services.AddSingleton<ICliCommand, WfpBlockCommand>();
        services.AddSingleton<ICliCommand, WfpUnblockCommand>();

        services.AddSingleton<ICliCommand, ListCommand>();
        services.AddSingleton<ICliCommand, QuarantineCommand>();
        services.AddSingleton<ICliCommand, RestoreCommand>();
        services.AddSingleton<ICliCommand, WatchCommand>();
        services.AddSingleton<ICliCommand, UpdateBlocklistCommand>();
        services.AddSingleton<ICliCommand, UpdateYaraRulesCommand>();
        services.AddSingleton<ICliCommand, MonitorCommand>();
        services.AddSingleton<ICliCommand, ConnectionsCommand>();
        services.AddSingleton<ICliCommand, DnsMonitorCommand>();
        services.AddSingleton<ICliCommand, DnsEventsCommand>();
        services.AddSingleton<ICliCommand, ProcessMonitorCommand>();
        services.AddSingleton<ICliCommand, ProcessEventsCommand>();

        services.AddSingleton<ICliCommand, ScanRootkitsCliCommand>();
        services.AddSingleton<ICliCommand, RootkitAlertsCommand>();
        services.AddSingleton<ICliCommand, ScanWmiCommand>();
        services.AddSingleton<ICliCommand, WmiAlertsCommand>();
        services.AddSingleton<ICliCommand, ScanComCommand>();
        services.AddSingleton<ICliCommand, ComAlertsCommand>();

        services.AddSingleton<ICliCommand, CheckUpdatesCliCommand>();
        services.AddSingleton<ICliCommand, ApplyUpdatesCliCommand>();
        services.AddSingleton<ICliCommand, VerifyIntegrityCommand>();
        services.AddSingleton<ICliCommand, SaveBaselineCliCommand>();
        services.AddSingleton<ICliCommand, ExportSiemCommand>();

        services.AddSingleton<ICliCommand, SnapshotMbrCliCommand>();
        services.AddSingleton<ICliCommand, CheckMbrCliCommand>();
        services.AddSingleton<ICliCommand, ScanUefiCliCommand>();

        services.AddSingleton<CliCommandRegistry>();
        return services;
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Scans;
using PerSourceAntivirus.Infrastructure.Config;
using PerSourceAntivirus.Infrastructure.Files;
using PerSourceAntivirus.Infrastructure.Metadata;
using PerSourceAntivirus.Infrastructure.Network;
using PerSourceAntivirus.Infrastructure.Office;
using PerSourceAntivirus.Infrastructure.Pe;
using PerSourceAntivirus.Infrastructure.Persistence;
using PerSourceAntivirus.Infrastructure.Process;
using PerSourceAntivirus.Infrastructure.Reputation;
using PerSourceAntivirus.Infrastructure.Scheduling;
using PerSourceAntivirus.Infrastructure.Scripts;
using PerSourceAntivirus.Infrastructure.Yara;

namespace PerSourceAntivirus.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlite(configuration.GetConnectionString("DefaultConnection")));

        services.AddScoped<IScannedFileRepository, ScannedFileRepository>();
        services.AddScoped<INetworkConnectionEventRepository, NetworkConnectionEventRepository>();
        services.AddScoped<IDnsEventRepository, DnsEventRepository>();
        services.AddScoped<IProcessEventRepository, ProcessEventRepository>();
        services.AddScoped<IScheduledScanRepository, ScheduledScanRepository>();
        services.AddScoped<FileScanService>();

        services.AddSingleton<IFileHashCalculator, FileHashCalculator>();
        services.AddSingleton<IPeAnalyzer, PeAnalyzer>();
        services.AddSingleton<IScriptAnalyzer, ScriptAnalyzer>();
        services.AddSingleton<IFileMetadataAnalyzer, MetadataExtractorAnalyzer>();
        services.AddSingleton<IOfficeMacroAnalyzer, OfficeMacroAnalyzer>();
        services.AddSingleton<INetworkMonitor, SharpPcapNetworkMonitor>();
        services.AddSingleton<IFileSystemMonitor, FileSystemWatcherMonitor>();
        services.AddSingleton<IExclusionList>(sp => new ConfiguredExclusionList(configuration));

        var maxParallelism = int.TryParse(configuration["Scan:MaxParallelism"], out var mp) ? mp : 0;
        if (maxParallelism <= 0) maxParallelism = Environment.ProcessorCount;
        services.AddSingleton(new ScanSettings(maxParallelism));

        // YARA rules directory
        var rulesDir = configuration["Yara:RulesDirectory"] ?? "data/yara-rules";
        if (!Path.IsPathRooted(rulesDir))
            rulesDir = Path.Combine(AppContext.BaseDirectory, rulesDir);

        var yaraScanner = new YaraScanner(rulesDir);
        services.AddSingleton<IYaraScanner>(yaraScanner);

        // YARA rules auto-update URLs
        var updateUrls = configuration.GetSection("Yara:UpdateUrls")
            .GetChildren()
            .Select(c => c.Value ?? string.Empty)
            .Where(v => v.Length > 0)
            .ToList();
        services.AddSingleton<IYaraRulesUpdater>(_ => new HttpYaraRulesUpdater(yaraScanner, rulesDir, updateUrls));

        // IP blocklist
        var blocklistFile = configuration["Network:IpBlocklistFile"] ?? "data/ip-blocklist.txt";
        if (!Path.IsPathRooted(blocklistFile))
            blocklistFile = Path.Combine(AppContext.BaseDirectory, blocklistFile);

        var blocklistProvider = new StaticBlocklistProvider(blocklistFile);
        services.AddSingleton<IBlocklistProvider>(blocklistProvider);

        var updateUrl = configuration["Network:BlocklistUpdateUrl"]
            ?? "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
        services.AddSingleton<IBlocklistUpdater>(
            _ => new HttpBlocklistUpdater(blocklistProvider, blocklistFile, updateUrl));

        // Domain blocklist for DNS monitoring
        var domainBlocklistFile = configuration["Network:DomainBlocklistFile"] ?? "data/domain-blocklist.txt";
        if (!Path.IsPathRooted(domainBlocklistFile))
            domainBlocklistFile = Path.Combine(AppContext.BaseDirectory, domainBlocklistFile);

        services.AddSingleton<IDomainBlocklist>(_ => new StaticDomainBlocklist(domainBlocklistFile));
        services.AddSingleton<IDnsMonitor, SharpPcapDnsMonitor>();

        // Process monitor (Windows WMI)
        services.AddSingleton<IProcessMonitor, WmiProcessMonitor>();

        // Quarantine
        var quarantineDir = configuration["Quarantine:Directory"] ?? "quarantine";
        if (!Path.IsPathRooted(quarantineDir))
            quarantineDir = Path.Combine(AppContext.BaseDirectory, quarantineDir);
        services.AddSingleton<IQuarantineService>(_ => new FileQuarantineService(quarantineDir));

        // Hash reputation
        var vtApiKey = configuration["Reputation:VirusTotalApiKey"] ?? string.Empty;
        var localHashFile = configuration["Reputation:LocalHashBlocklistFile"] ?? "data/known-malicious-hashes.txt";
        if (!Path.IsPathRooted(localHashFile))
            localHashFile = Path.Combine(AppContext.BaseDirectory, localHashFile);

        var localReputation = new LocalHashReputationService(localHashFile);
        var vtReputation = new VirusTotalHashReputationService(vtApiKey);
        services.AddSingleton<IHashReputationService>(_ => new CompositeHashReputationService(localReputation, vtReputation));

        // Scheduled scan background service
        services.AddHostedService<ScanSchedulerService>();

        return services;
    }
}

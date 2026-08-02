using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Scans;
using PerSourceAntivirus.Infrastructure.Amsi;
using PerSourceAntivirus.Infrastructure.Archive;
using PerSourceAntivirus.Infrastructure.ComHijack;
using PerSourceAntivirus.Infrastructure.Config;
using PerSourceAntivirus.Infrastructure.Cryptojacking;
using PerSourceAntivirus.Infrastructure.Dga;
using PerSourceAntivirus.Infrastructure.DllHijack;
using PerSourceAntivirus.Infrastructure.Email;
using PerSourceAntivirus.Infrastructure.Emulation;
using PerSourceAntivirus.Infrastructure.Etw;
using PerSourceAntivirus.Infrastructure.Fileless;
using PerSourceAntivirus.Infrastructure.Files;
using PerSourceAntivirus.Infrastructure.LolBin;
using PerSourceAntivirus.Infrastructure.Mbr;
using PerSourceAntivirus.Infrastructure.Metadata;
using PerSourceAntivirus.Infrastructure.Minifilter;
using PerSourceAntivirus.Infrastructure.Ransomware;
using PerSourceAntivirus.Infrastructure.Persistence;
using PerSourceAntivirus.Infrastructure.Network;
using PerSourceAntivirus.Infrastructure.Office;
using PerSourceAntivirus.Infrastructure.Packing;
using PerSourceAntivirus.Infrastructure.Pdf;
using PerSourceAntivirus.Infrastructure.Pe;
using PerSourceAntivirus.Infrastructure.Process;
using PerSourceAntivirus.Infrastructure.ProcessInjection;
using PerSourceAntivirus.Infrastructure.Reputation;
using PerSourceAntivirus.Infrastructure.Rootkit;
using PerSourceAntivirus.Infrastructure.Sandbox;
using PerSourceAntivirus.Infrastructure.Scheduling;
using PerSourceAntivirus.Infrastructure.Scripts;
using PerSourceAntivirus.Infrastructure.SelfIntegrity;
using PerSourceAntivirus.Infrastructure.Siem;
using PerSourceAntivirus.Infrastructure.Signatures;
using PerSourceAntivirus.Infrastructure.Signing;
using PerSourceAntivirus.Infrastructure.Steganography;
using PerSourceAntivirus.Infrastructure.ThreatFeeds;
using PerSourceAntivirus.Infrastructure.Tls;
using PerSourceAntivirus.Infrastructure.Uefi;
using PerSourceAntivirus.Infrastructure.Updates;
using PerSourceAntivirus.Infrastructure.Wmi;
using PerSourceAntivirus.Infrastructure.Kernel;
using PerSourceAntivirus.Infrastructure.Behavioral;
using PerSourceAntivirus.Infrastructure.Forensics;
using PerSourceAntivirus.Infrastructure.Reporting;
using PerSourceAntivirus.Infrastructure.Wsc;
using PerSourceAntivirus.Infrastructure.Yara;
using InfraSystem = PerSourceAntivirus.Infrastructure.SystemIntegration;
using PerSourceAntivirus.Infrastructure.Composition;

namespace PerSourceAntivirus.Infrastructure;

// YARA, blocklists, process monitoring, quarantine and hash reputation.
// Extracted from the former ~580-line AddInfrastructureServices (ADR-002). Registration
// order within and across modules is preserved exactly as it was.
internal static class ScanningEngineServices
{
    public static IServiceCollection AddScanningEngineServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        // YARA — the scanner instance and its rules directory come from the shared build context
        // so the auto-updater below reloads the very same instance the engine scans with.
        services.AddSingleton<IYaraScanner>(ctx.YaraScanner);

        // YARA rules auto-update URLs
        var updateUrls = configuration.GetSection("Yara:UpdateUrls")
            .GetChildren()
            .Select(c => c.Value ?? string.Empty)
            .Where(v => v.Length > 0)
            .ToList();
        services.AddSingleton<IYaraRulesUpdater>(_ => new HttpYaraRulesUpdater(ctx.YaraScanner, ctx.YaraRulesDirectory, updateUrls));

        // IP blocklist
        services.AddSingleton<IBlocklistProvider>(ctx.BlocklistProvider);

        var updateUrl = configuration["Network:BlocklistUpdateUrl"]
            ?? "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
        services.AddSingleton<IBlocklistUpdater>(
            _ => new HttpBlocklistUpdater(ctx.BlocklistProvider, ctx.IpBlocklistFile, updateUrl));

        // Domain blocklist for DNS monitoring
        services.AddSingleton<IDomainBlocklist>(ctx.DomainBlocklist);
        services.AddSingleton<IDnsMonitor, SharpPcapDnsMonitor>();

        // Process monitor (Windows WMI) + snapshot provider for check-running
        services.AddSingleton<IProcessMonitor, WmiProcessMonitor>();
        services.AddSingleton<IRunningProcessProvider, SystemRunningProcessProvider>();

        // Quarantine
        services.AddSingleton<IQuarantineService>(_ => new FileQuarantineService(ctx.QuarantineDirectory));

        // Hash reputation
        var vtApiKey = configuration["Reputation:VirusTotalApiKey"] ?? string.Empty;
        var vtReputation = new VirusTotalHashReputationService(vtApiKey);
        services.AddSingleton<IHashReputationService>(_ => new CompositeHashReputationService(ctx.LocalReputation, vtReputation));

        return services;
    }
}

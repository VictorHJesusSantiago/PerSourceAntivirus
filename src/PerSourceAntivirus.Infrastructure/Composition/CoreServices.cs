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

internal static class CoreServices
{
    public static IServiceCollection AddCoreServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
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

        return services;
    }
}

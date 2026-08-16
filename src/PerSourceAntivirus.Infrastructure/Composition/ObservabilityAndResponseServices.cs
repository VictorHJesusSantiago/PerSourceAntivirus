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

internal static class ObservabilityAndResponseServices
{
    public static IServiceCollection AddObservabilityAndResponseServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        services.AddSingleton<IMetricsExporter, PerSourceAntivirus.Infrastructure.Reporting.PrometheusMetricsExporter>();
        services.AddSingleton<ISyslogCefIngestionService, PerSourceAntivirus.Infrastructure.Siem.SyslogCefIngestionService>();
        services.AddScoped<IRemoteAgentEventRepository, PerSourceAntivirus.Infrastructure.Siem.RemoteAgentEventRepository>();
        services.AddScoped<IAuditLogChainService, PerSourceAntivirus.Infrastructure.Security.AuditLogChainService>();

        var otxApiKey = configuration["ThreatIntel:OtxApiKey"] ?? string.Empty;
        var threatIntelCacheDir = Path.Combine(AppContext.BaseDirectory, "data", "threat-intel-cache");
        services.AddSingleton<IThreatFeedUpdater>(sp => new PerSourceAntivirus.Infrastructure.ThreatFeeds.ThreatFoxUpdater(
            sp.GetRequiredService<IServiceScopeFactory>(),
            ctx.BlocklistProvider, ctx.IpBlocklistFile, ctx.DomainBlocklist, ctx.DomainBlocklistFile,
            Path.Combine(threatIntelCacheDir, "threatfox.cache.json"),
            sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new PerSourceAntivirus.Infrastructure.ThreatFeeds.OtxThreatFeedUpdater(
            otxApiKey, sp.GetRequiredService<IServiceScopeFactory>(),
            ctx.BlocklistProvider, ctx.IpBlocklistFile, ctx.DomainBlocklist, ctx.DomainBlocklistFile,
            Path.Combine(threatIntelCacheDir, "otx.cache.json"),
            sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new PerSourceAntivirus.Infrastructure.ThreatFeeds.PhishTankUpdater(
            sp.GetRequiredService<IServiceScopeFactory>(), ctx.DomainBlocklist, ctx.DomainBlocklistFile,
            Path.Combine(threatIntelCacheDir, "phishtank.cache.json"),
            sp.GetRequiredService<IHttpClientFactory>()));

        services.AddSingleton<IIpDomainReputationScoringService, PerSourceAntivirus.Infrastructure.Reputation.IpDomainReputationScoringService>();
        services.AddScoped<IStixIocExporter, PerSourceAntivirus.Infrastructure.ThreatIntel.StixIocExporter>();

        services.AddSingleton<IHostIsolationService, PerSourceAntivirus.Infrastructure.Network.HostIsolationService>();
        services.AddScoped<IHostIsolationEventRepository, PerSourceAntivirus.Infrastructure.Network.HostIsolationEventRepository>();

        var samplePackageDir = Path.Combine(AppContext.BaseDirectory, "data", "sample-submissions");
        services.AddSingleton<ISampleSubmissionService>(sp => new PerSourceAntivirus.Infrastructure.Files.SampleSubmissionService(
            sp.GetRequiredService<IServiceScopeFactory>(), sp.GetRequiredService<IHttpClientFactory>(), samplePackageDir));
        services.AddScoped<ISampleSubmissionRepository, PerSourceAntivirus.Infrastructure.Files.SampleSubmissionRepository>();

        services.AddScoped<IResponsePlaybookRuleRepository, PerSourceAntivirus.Infrastructure.Response.ResponsePlaybookRuleRepository>();
        services.AddScoped<IPlaybookExecutionLogRepository, PerSourceAntivirus.Infrastructure.Response.PlaybookExecutionLogRepository>();
        services.AddSingleton<IResponsePlaybookEngine>(sp => new PerSourceAntivirus.Infrastructure.Response.ResponsePlaybookEngine(
            sp.GetRequiredService<IServiceScopeFactory>(), ctx.QuarantineDirectory));

        services.AddSingleton<ISystemRestoreService, PerSourceAntivirus.Infrastructure.SystemIntegration.SystemRestoreService>();

        services.AddSingleton<IDetectorDiagnostics, PerSourceAntivirus.Infrastructure.Diagnostics.DetectorDiagnostics>();

        services.AddHostedService<RealtimeProtectionHostedService>();

        return services;
    }
}

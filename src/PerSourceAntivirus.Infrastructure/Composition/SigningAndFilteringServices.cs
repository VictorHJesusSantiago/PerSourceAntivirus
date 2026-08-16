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

internal static class SigningAndFilteringServices
{
    public static IServiceCollection AddSigningAndFilteringServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        services.AddSingleton<IDllHijackDetector, DllHijackDetector>();
        services.AddScoped<IDllHijackAlertRepository, DllHijackAlertRepository>();

        services.AddSingleton<ICryptojackingDetector, CryptojackingDetector>();
        services.AddScoped<ICryptojackingAlertRepository, CryptojackingAlertRepository>();

        services.AddSingleton<IAuthenticodeVerifier, AuthenticodeVerifier>();
        services.AddSingleton<IUnsignedBinaryDetector, UnsignedBinaryDetector>();
        services.AddScoped<IUnsignedBinaryAlertRepository, UnsignedBinaryAlertRepository>();

        var customSignaturesFile = configuration["Signatures:CustomSignaturesFile"] ?? "data/custom-signatures.txt";
        if (!Path.IsPathRooted(customSignaturesFile))
            customSignaturesFile = Path.Combine(AppContext.BaseDirectory, customSignaturesFile);
        services.AddSingleton<ICustomSignatureEngine>(_ => new CustomSignatureEngine(customSignaturesFile));
        services.AddScoped<ICustomSignatureMatchRepository, CustomSignatureMatchRepository>();

        services.AddScoped<ICertificateTrustEntryRepository, CertificateTrustEntryRepository>();
        services.AddSingleton<ICertificateTrustListService, CertificateTrustListService>();
        services.AddSingleton<ICertificateTrustDetector, CertificateTrustDetector>();
        services.AddScoped<ICertificateTrustAlertRepository, CertificateTrustAlertRepository>();

        var domainBlocklistFileForHosts = configuration["Network:DomainBlocklistFile"] ?? "data/domain-blocklist.txt";
        if (!Path.IsPathRooted(domainBlocklistFileForHosts))
            domainBlocklistFileForHosts = Path.Combine(AppContext.BaseDirectory, domainBlocklistFileForHosts);
        services.AddSingleton<IHostsFileBlocklistService>(_ => new HostsFileBlocklistService(domainBlocklistFileForHosts));

        services.AddScoped<IProcessFirewallRuleRepository, ProcessFirewallRuleRepository>();
        services.AddSingleton<IProcessFirewallService, ProcessFirewallService>();

        services.AddSingleton<IDnsTunnelingDetector, DnsTunnelingDetector>();
        services.AddScoped<IDnsTunnelingAlertRepository, DnsTunnelingAlertRepository>();

        var geoIpDatabaseFile = configuration["GeoIp:DatabaseFile"] ?? "data/geoip-country-ranges.csv";
        if (!Path.IsPathRooted(geoIpDatabaseFile))
            geoIpDatabaseFile = Path.Combine(AppContext.BaseDirectory, geoIpDatabaseFile);
        var blockedCountries = configuration.GetSection("GeoIp:BlockedCountries")
            .GetChildren().Select(c => c.Value ?? string.Empty).Where(v => v.Length > 0).ToList();
        services.AddSingleton<IGeoIpBlockingService>(_ => new GeoIpBlockingService(geoIpDatabaseFile, blockedCountries));
        services.AddSingleton<IGeoIpEnforcementDetector, GeoIpEnforcementDetector>();
        services.AddScoped<IGeoIpBlockAlertRepository, GeoIpBlockAlertRepository>();

        services.AddSingleton<IFullScreenDetector, PerSourceAntivirus.Infrastructure.SystemIntegration.FullScreenDetector>();
        var reportsDir = Path.Combine(AppContext.BaseDirectory, "data", "reports");
        services.AddHostedService(sp => new PerSourceAntivirus.Infrastructure.Reporting.ThreatReportSchedulerService(
            sp.GetRequiredService<IServiceScopeFactory>(), reportsDir));

        services.AddSingleton<IExplorerContextMenuInstaller, PerSourceAntivirus.Infrastructure.SystemIntegration.ExplorerContextMenuInstaller>();
        services.AddSingleton<ISecureBootVerifier, PerSourceAntivirus.Infrastructure.Uefi.SecureBootVerifier>();
        services.AddScoped<ISecureBootSnapshotRepository, PerSourceAntivirus.Infrastructure.Uefi.SecureBootSnapshotRepository>();

        var usbAllowlistFile = configuration["UsbControl:AllowlistFile"] ?? "data/usb-allowlist.txt";
        if (!Path.IsPathRooted(usbAllowlistFile))
            usbAllowlistFile = Path.Combine(AppContext.BaseDirectory, usbAllowlistFile);
        services.AddSingleton<IUsbDeviceControlService>(sp => new PerSourceAntivirus.Infrastructure.SystemIntegration.UsbDeviceControlService(
            sp.GetRequiredService<IServiceScopeFactory>(), usbAllowlistFile));
        services.AddScoped<IUsbDeviceEventRepository, PerSourceAntivirus.Infrastructure.SystemIntegration.UsbDeviceEventRepository>();

        var activeLearningWeightsFile = Path.Combine(AppContext.BaseDirectory, "data", "models", "active-learning-weights.json");
        services.AddSingleton<IActiveLearningService>(sp => new PerSourceAntivirus.Infrastructure.Pe.ActiveLearningService(
            sp.GetRequiredService<IServiceScopeFactory>(), activeLearningWeightsFile));
        services.AddScoped<IActiveLearningSampleRepository, PerSourceAntivirus.Infrastructure.Pe.ActiveLearningSampleRepository>();

        return services;
    }
}

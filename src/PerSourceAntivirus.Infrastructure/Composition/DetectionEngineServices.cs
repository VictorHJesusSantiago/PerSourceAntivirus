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

// Phase 13-14 detection engines and exploit-prevention detectors.
// Extracted from the former ~580-line AddInfrastructureServices (ADR-002). Registration
// order within and across modules is preserved exactly as it was.
internal static class DetectionEngineServices
{
    public static IServiceCollection AddDetectionEngineServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        // Phase 13 â€” new detection engines
        services.AddSingleton<ICpuEmulator, X86CpuEmulator>();
        services.AddSingleton<IPackerDetector, PackerDetector>();
        services.AddSingleton<IAmsiProvider, AmsiProviderService>();
        services.AddSingleton<IWscRegistration, WscRegistrationService>();
        services.AddSingleton<ILolBinDetector, LolBinDetector>();
        services.AddScoped<ILolBinAlertRepository, LolBinAlertRepository>();
        services.AddSingleton<IFilelessDetector, FilelessMalwareDetector>();
        services.AddScoped<IFilelessAlertRepository, FilelessAlertRepository>();
        services.AddSingleton<IDgaDetector, DgaDetector>();
        services.AddScoped<IDgaAlertRepository, DgaAlertRepository>();
        services.AddSingleton<IAdsScanner, AdsScanner>();
        services.AddSingleton<IArchiveScanner, SharpCompressArchiveScanner>();
        services.AddSingleton<IPdfScanner, PdfPigScanner>();
        services.AddSingleton<IEmailScanner, MimeKitEmailScanner>();
        services.AddSingleton<ISteganographyDetector, LsbSteganographyDetector>();

        // Phase 14 â€” Advanced exploit prevention
        services.AddSingleton<IProcessHollowingDetector, ProcessHollowingDetector>();
        services.AddScoped<IProcessHollowingAlertRepository, ProcessHollowingAlertRepository>();
        services.AddSingleton<IProcessDoppelgangingDetector, ProcessDoppelgangingDetector>();
        services.AddScoped<IProcessDoppelgangingAlertRepository, ProcessDoppelgangingAlertRepository>();
        services.AddSingleton<IReflectiveDllInjectionDetector, ReflectiveDllInjectionDetector>();
        services.AddScoped<IReflectiveDllInjectionAlertRepository, ReflectiveDllInjectionAlertRepository>();
        services.AddSingleton<IAtomBombingDetector, AtomBombingDetector>();
        services.AddScoped<IAtomBombingAlertRepository, AtomBombingAlertRepository>();
        services.AddSingleton<IHeavensGateDetector, HeavensGateDetector>();
        services.AddScoped<IHeavensGateAlertRepository, HeavensGateAlertRepository>();
        services.AddSingleton<INtdllUnhookingDetector, NtdllUnhookingDetector>();
        services.AddScoped<INtdllUnhookingAlertRepository, NtdllUnhookingAlertRepository>();
        services.AddSingleton<IDirectSyscallDetector, DirectSyscallDetector>();
        services.AddScoped<IDirectSyscallAlertRepository, DirectSyscallAlertRepository>();
        services.AddSingleton<IHeapSprayDetector, HeapSprayDetector>();
        services.AddScoped<IHeapSprayAlertRepository, HeapSprayAlertRepository>();
        services.AddSingleton<IStackPivotDetector, StackPivotDetector>();
        services.AddScoped<IStackPivotAlertRepository, StackPivotAlertRepository>();
        services.AddSingleton<IProcessGhostingDetector, ProcessGhostingDetector>();
        services.AddScoped<IProcessGhostingAlertRepository, ProcessGhostingAlertRepository>();
        services.AddSingleton<IModuleStompingDetector, ModuleStompingDetector>();
        services.AddScoped<IModuleStompingAlertRepository, ModuleStompingAlertRepository>();
        services.AddSingleton<ITransactedHollowingDetector, TransactedHollowingDetector>();
        services.AddScoped<ITransactedHollowingAlertRepository, TransactedHollowingAlertRepository>();

        return services;
    }
}

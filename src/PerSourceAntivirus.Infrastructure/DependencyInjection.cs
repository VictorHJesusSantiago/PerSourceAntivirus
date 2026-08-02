using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Composition;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure;

// Composition root. [ADR-002] This used to be a single ~580-line method with ~200 registrations,
// where a wrong lifetime was effectively invisible in review — the audit found 14 singletons
// capturing scoped repositories hiding in it. The registrations now live in themed modules under
// Composition/, and DependencyInjectionGraphTests enforces the lifetime rules mechanically.
public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
    {
        AddHttpClients(services);
        AddEncryptedDbContext(services, configuration);

        // Paths and the shared provider instances are computed once and handed to every module,
        // so no two modules can construct competing copies of the same blocklist/scanner.
        var ctx = InfrastructureBuildContext.Create(configuration);

        services
            .AddCoreServices(configuration, ctx)
            .AddScanningEngineServices(configuration, ctx)
            .AddPlatformServices(configuration, ctx)
            .AddDetectionEngineServices(configuration, ctx)
            .AddNetworkAndAuditServices(configuration, ctx)
            .AddBehavioralServices(configuration, ctx)
            .AddSigningAndFilteringServices(configuration, ctx)
            .AddObservabilityAndResponseServices(configuration, ctx);

        return services;
    }

    // [AUDIT FIX — Domain 15] Every HTTP-calling service used to hold its own `new HttpClient()`
    // (socket exhaustion + DNS that never refreshes) or share one process-wide static instance
    // (no handler rotation). IHttpClientFactory pools and recycles handlers; services now call
    // CreateClient() per request against these named policies.
    private static void AddHttpClients(IServiceCollection services)
    {
        services.AddHttpClient(PerSourceAntivirus.Infrastructure.ThreatFeeds.ThreatFeedHttpClient.Name, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(60);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("PerSourceAntivirus/1.0");
        });
        services.AddHttpClient(PerSourceAntivirus.Infrastructure.Siem.SyslogCefExporter.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
        });
    }

    // Encrypt persourceav.db at rest via SQLCipher. The e_sqlcipher provider transparently
    // reads existing plaintext databases too, so this is safe to set unconditionally;
    // DatabaseEncryptionMigrator then converts any pre-existing plaintext file in place.
    private static void AddEncryptedDbContext(IServiceCollection services, IConfiguration configuration)
    {
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_e_sqlcipher());

        var baseConnectionString = configuration.GetConnectionString("DefaultConnection")
            ?? "Data Source=persourceav.db";
        var dbKeyFile = Path.Combine(AppContext.BaseDirectory, "data", "db.key");
        var dbPassphrase = DatabaseEncryptionKeyProvider.GetOrCreatePassphrase(dbKeyFile);

        var dbFilePathMatch = System.Text.RegularExpressions.Regex.Match(baseConnectionString, @"Data Source=([^;]+)");
        if (dbFilePathMatch.Success)
        {
            var dbFilePath = dbFilePathMatch.Groups[1].Value;
            if (!Path.IsPathRooted(dbFilePath)) dbFilePath = Path.Combine(AppContext.BaseDirectory, dbFilePath);
            DatabaseEncryptionMigrator.EnsureEncrypted(dbFilePath, dbPassphrase);
        }

        var encryptedConnectionString = $"{baseConnectionString};Password={dbPassphrase}";
        services.AddDbContext<AppDbContext>(options => options.UseSqlite(encryptedConnectionString));
    }
}

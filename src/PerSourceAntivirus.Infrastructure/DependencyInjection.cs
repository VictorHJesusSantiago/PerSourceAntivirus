using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Composition;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
    {
        AddHttpClients(services);
        AddEncryptedDbContext(services, configuration);

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

using Microsoft.Extensions.Configuration;
using PerSourceAntivirus.Infrastructure.Network;
using PerSourceAntivirus.Infrastructure.Reputation;
using PerSourceAntivirus.Infrastructure.Yara;

namespace PerSourceAntivirus.Infrastructure.Composition;

internal sealed class InfrastructureBuildContext
{
    public required string YaraRulesDirectory { get; init; }
    public required YaraScanner YaraScanner { get; init; }

    public required string IpBlocklistFile { get; init; }
    public required StaticBlocklistProvider BlocklistProvider { get; init; }

    public required string DomainBlocklistFile { get; init; }
    public required StaticDomainBlocklist DomainBlocklist { get; init; }

    public required string LocalHashFile { get; init; }
    public required LocalHashReputationService LocalReputation { get; init; }

    public required string QuarantineDirectory { get; init; }
    public required string ModelsDirectory { get; init; }

    public static InfrastructureBuildContext Create(IConfiguration configuration)
    {
        var yaraRulesDirectory = ResolvePath(configuration["Yara:RulesDirectory"], "data/yara-rules");
        var ipBlocklistFile = ResolvePath(configuration["Network:IpBlocklistFile"], "data/ip-blocklist.txt");
        var domainBlocklistFile = ResolvePath(configuration["Network:DomainBlocklistFile"], "data/domain-blocklist.txt");
        var localHashFile = ResolvePath(configuration["Reputation:LocalHashBlocklistFile"], "data/known-malicious-hashes.txt");
        var quarantineDirectory = ResolvePath(configuration["Quarantine:Directory"], "quarantine");
        var modelsDirectory = Path.Combine(AppContext.BaseDirectory, "data", "models");
        Directory.CreateDirectory(modelsDirectory);

        return new InfrastructureBuildContext
        {
            YaraRulesDirectory = yaraRulesDirectory,
            YaraScanner = new YaraScanner(yaraRulesDirectory),
            IpBlocklistFile = ipBlocklistFile,
            BlocklistProvider = new StaticBlocklistProvider(ipBlocklistFile),
            DomainBlocklistFile = domainBlocklistFile,
            DomainBlocklist = new StaticDomainBlocklist(domainBlocklistFile),
            LocalHashFile = localHashFile,
            LocalReputation = new LocalHashReputationService(localHashFile),
            QuarantineDirectory = quarantineDirectory,
            ModelsDirectory = modelsDirectory
        };
    }

    internal static string ResolvePath(string? configured, string fallback)
    {
        var value = string.IsNullOrWhiteSpace(configured) ? fallback : configured;
        return Path.IsPathRooted(value) ? value : Path.Combine(AppContext.BaseDirectory, value);
    }
}

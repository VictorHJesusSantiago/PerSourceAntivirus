using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Infrastructure;

namespace PerSourceAntivirus.Infrastructure.Tests;

public class DependencyInjectionGraphTests
{
    private static ServiceCollection BuildRegistrations()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = $"Data Source={Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".db")}"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddInfrastructureServices(configuration);
        return services;
    }

    [Fact]
    public void NoSingleton_DependsOnAScopedService()
    {
        var services = BuildRegistrations();

        var lifetimeByServiceType = services
            .GroupBy(d => d.ServiceType)
            .ToDictionary(g => g.Key, g => g.Last().Lifetime);

        var violations = new List<string>();

        foreach (var descriptor in services.Where(d => d.Lifetime == ServiceLifetime.Singleton))
        {
            var implementationType = descriptor.ImplementationType;
            if (implementationType is null) continue;

            var constructor = implementationType.GetConstructors()
                .OrderByDescending(c => c.GetParameters().Length)
                .FirstOrDefault();
            if (constructor is null) continue;

            foreach (var parameter in constructor.GetParameters())
            {
                if (lifetimeByServiceType.TryGetValue(parameter.ParameterType, out var lifetime) &&
                    lifetime == ServiceLifetime.Scoped)
                {
                    violations.Add(
                        $"{implementationType.Name} (Singleton) captures {parameter.ParameterType.Name} (Scoped)");
                }
            }
        }

        violations.Should().BeEmpty(
            "a singleton that captures a scoped service pins one AppDbContext for the process " +
            "lifetime and writes to it concurrently — use IServiceScopeFactory + scope-per-write " +
            "instead. Offenders: {0}", string.Join(" | ", violations));
    }

    [Fact]
    public void EveryServiceType_IsRegistered_ForItsOwnImplementationDependencies()
    {
        var services = BuildRegistrations();
        var registered = services.Select(d => d.ServiceType).ToHashSet();

        var missing = new List<string>();

        foreach (var descriptor in services)
        {
            var implementationType = descriptor.ImplementationType;
            if (implementationType is null) continue;
            if (implementationType.ContainsGenericParameters) continue;

            var constructor = implementationType.GetConstructors()
                .OrderByDescending(c => c.GetParameters().Length)
                .FirstOrDefault();
            if (constructor is null) continue;

            foreach (var parameter in constructor.GetParameters())
            {
                if (parameter.HasDefaultValue) continue;
                if (registered.Contains(parameter.ParameterType)) continue;
                if (IsFrameworkProvided(parameter.ParameterType)) continue;

                if (parameter.ParameterType.IsGenericType &&
                    registered.Contains(parameter.ParameterType.GetGenericTypeDefinition())) continue;

                missing.Add($"{implementationType.Name} needs {parameter.ParameterType.Name}");
            }
        }

        missing.Should().BeEmpty();
    }

    private static bool IsFrameworkProvided(Type type)
    {
        var name = type.FullName ?? type.Name;
        return name.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal)
            || name.StartsWith("Microsoft.EntityFrameworkCore.", StringComparison.Ordinal)
            || name.StartsWith("System.", StringComparison.Ordinal)
            || type == typeof(string)
            || type.IsValueType;
    }

    [Fact]
    public void RealtimeDetectors_AreRegisteredAsSingletons()
    {
        var services = BuildRegistrations();

        var detectorRegistrations = services
            .Where(d => d.ServiceType.Name.EndsWith("Detector", StringComparison.Ordinal)
                     || d.ServiceType.Name.EndsWith("Monitor", StringComparison.Ordinal))
            .ToList();

        detectorRegistrations.Should().NotBeEmpty("the detector registrations should be discoverable by name");
        detectorRegistrations.Should().OnlyContain(d => d.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AlertRepositories_AreRegisteredAsScoped()
    {
        var services = BuildRegistrations();

        var repositoryRegistrations = services
            .Where(d => d.ServiceType.Name.EndsWith("Repository", StringComparison.Ordinal))
            .ToList();

        repositoryRegistrations.Should().NotBeEmpty();
        repositoryRegistrations.Should().OnlyContain(d => d.Lifetime == ServiceLifetime.Scoped);
    }
}

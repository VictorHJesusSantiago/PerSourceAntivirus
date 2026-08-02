using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Infrastructure;

namespace PerSourceAntivirus.Infrastructure.Tests;

// Guards the composition root itself. The audit found seven singleton detectors that injected a
// *scoped* repository — each captured one AppDbContext for the process lifetime and wrote to it
// from background scan threads, where it is not thread-safe. Nothing caught that: the DI container
// only reports captive dependencies when scope validation is on (Development-only by default), and
// the detectors were never started, so the bug stayed dormant until they were.
//
// These tests inspect the service descriptors directly — no instantiation, so they run on any
// machine regardless of admin rights or native dependencies.
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
            // Only concrete-type registrations expose a constructor to inspect. Factory
            // registrations (sp => new X(...)) resolve lazily and are checked by the
            // scope-factory convention test below instead.
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
        // Catches a registration that can never be constructed because one of its dependencies
        // was forgotten — the failure would otherwise only surface at runtime, on first resolve.
        var services = BuildRegistrations();
        var registered = services.Select(d => d.ServiceType).ToHashSet();

        var missing = new List<string>();

        foreach (var descriptor in services)
        {
            var implementationType = descriptor.ImplementationType;
            if (implementationType is null) continue;
            // Open generic registrations (e.g. IOptionsMonitor<>) cannot be resolved statically:
            // their parameter types are type variables with no FullName to match against.
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

                // Open generics such as ILogger<T> are satisfied by the logging infrastructure.
                if (parameter.ParameterType.IsGenericType &&
                    registered.Contains(parameter.ParameterType.GetGenericTypeDefinition())) continue;

                missing.Add($"{implementationType.Name} needs {parameter.ParameterType.Name}");
            }
        }

        missing.Should().BeEmpty();
    }

    // Anything the hosting/framework layer supplies rather than this project's composition root.
    // Microsoft.Extensions.* registrations (options, logging, http) are added by AddHttpClient /
    // AddDbContext / the generic host and are not ours to assert on.
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
        // Detectors hold per-process dedup state (_alerted, _recentAlerts). Registering one as
        // Transient or Scoped would silently reset that state and produce duplicate alerts.
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
        // The mirror of the rule above: repositories wrap AppDbContext and must never be
        // singletons, or every writer would share one non-thread-safe context.
        var services = BuildRegistrations();

        var repositoryRegistrations = services
            .Where(d => d.ServiceType.Name.EndsWith("Repository", StringComparison.Ordinal))
            .ToList();

        repositoryRegistrations.Should().NotBeEmpty();
        repositoryRegistrations.Should().OnlyContain(d => d.Lifetime == ServiceLifetime.Scoped);
    }
}

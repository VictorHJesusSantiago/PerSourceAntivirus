using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record HuntQueryFilters(
    int? ProcessId,
    string? ProcessName,
    string? FilePath,
    string? RegistryKey,
    string? IpAddress,
    int? Port,
    string? Hash,
    DateTime? From,
    DateTime? To,
    int MaxResults = 1000);

public record HuntQueryResults(
    IReadOnlyList<ProcessCreationEvent> Processes,
    IReadOnlyList<FileActivityEvent> Files,
    IReadOnlyList<RegistryActivityEvent> Registry,
    IReadOnlyList<NetworkConnectionEvent> Network,
    int TotalCount);

public interface IHuntQueryService
{
    Task<HuntQueryResults> QueryAsync(HuntQueryFilters filters, CancellationToken ct = default);
}

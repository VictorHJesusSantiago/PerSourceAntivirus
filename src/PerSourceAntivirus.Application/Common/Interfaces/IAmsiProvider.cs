namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAmsiProvider
{
    Task RegisterAsync(CancellationToken ct = default);
    Task UnregisterAsync(CancellationToken ct = default);
    bool IsRegistered { get; }
}

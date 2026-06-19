namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWscRegistration
{
    Task RegisterAsync(CancellationToken ct = default);
    Task UnregisterAsync(CancellationToken ct = default);
    bool IsRegistered { get; }
}

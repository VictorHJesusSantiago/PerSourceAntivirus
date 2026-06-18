namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBootExecuteService
{
    Task RegisterAsync(CancellationToken ct = default);
    Task UnregisterAsync(CancellationToken ct = default);
    Task<bool> IsRegisteredAsync(CancellationToken ct = default);
}

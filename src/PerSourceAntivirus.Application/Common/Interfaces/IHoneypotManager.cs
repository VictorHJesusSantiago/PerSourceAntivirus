namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHoneypotManager
{
    Task<IReadOnlyList<string>> SetupHoneypotsAsync(CancellationToken ct = default);
}

using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISensitiveDataScanner
{
    IReadOnlyList<string> SupportedDataTypes { get; }
    IAsyncEnumerable<SensitiveDataFinding> ScanAsync(string rootPath, CancellationToken ct);
}

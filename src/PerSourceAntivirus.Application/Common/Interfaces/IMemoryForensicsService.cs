using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMemoryForensicsService
{
    Task<MemoryDumpResult> DumpAndAnalyzeAsync(int processId, string outputDirectory, CancellationToken ct = default);
}

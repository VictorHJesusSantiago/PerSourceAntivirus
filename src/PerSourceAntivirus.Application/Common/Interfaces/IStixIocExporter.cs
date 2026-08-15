namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IStixIocExporter
{
    Task<string> ExportToFileAsync(string outputFilePath, CancellationToken ct = default);
}

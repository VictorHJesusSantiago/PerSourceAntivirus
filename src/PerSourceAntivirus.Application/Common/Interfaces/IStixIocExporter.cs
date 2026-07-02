namespace PerSourceAntivirus.Application.Common.Interfaces;

// Exports locally-collected IOCs (CustomIoc + previously-imported StixIoc) as a STIX 2.1
// bundle so the local threat intel this install has accumulated can be shared with the
// community / fed into another CTI platform.
public interface IStixIocExporter
{
    Task<string> ExportToFileAsync(string outputFilePath, CancellationToken ct = default);
}

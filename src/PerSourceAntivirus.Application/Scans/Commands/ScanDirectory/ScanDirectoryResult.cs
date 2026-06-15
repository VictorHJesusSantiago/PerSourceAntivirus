namespace PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;

public record ScanDirectoryResult(int FilesScanned, TimeSpan Duration);

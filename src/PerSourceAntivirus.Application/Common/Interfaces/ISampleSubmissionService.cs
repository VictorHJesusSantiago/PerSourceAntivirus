namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISampleSubmissionService
{
    Task<string> PackageSampleAsync(string quarantinedFilePath, CancellationToken ct = default);
    Task<bool> SubmitAsync(string packagedArchivePath, string submissionUrl, CancellationToken ct = default);
}

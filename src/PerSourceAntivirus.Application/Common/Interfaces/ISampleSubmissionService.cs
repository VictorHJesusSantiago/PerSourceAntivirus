namespace PerSourceAntivirus.Application.Common.Interfaces;

// Packages a quarantined file into a zip archive for manual/opt-in submission to an external
// analysis service. Packaging never happens automatically — the operator explicitly triggers
// both steps, and SubmitAsync only runs when a submission URL is supplied.
public interface ISampleSubmissionService
{
    Task<string> PackageSampleAsync(string quarantinedFilePath, CancellationToken ct = default);
    Task<bool> SubmitAsync(string packagedArchivePath, string submissionUrl, CancellationToken ct = default);
}

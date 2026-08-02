using System.IO.Compression;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Files;

public sealed class SampleSubmissionService(
    IServiceScopeFactory scopeFactory,
    IHttpClientFactory httpClientFactory,
    string packageDirectory)
    : ISampleSubmissionService
{
    public async Task<string> PackageSampleAsync(string quarantinedFilePath, CancellationToken ct = default)
    {
        if (!File.Exists(quarantinedFilePath))
            throw new FileNotFoundException("Quarantined file not found", quarantinedFilePath);

        Directory.CreateDirectory(packageDirectory);

        var archiveName = $"{Path.GetFileNameWithoutExtension(quarantinedFilePath)}_{DateTime.UtcNow:yyyyMMddHHmmss}.zip";
        var archivePath = Path.Combine(packageDirectory, archiveName);

        using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        {
            // .bin extension inside the archive to avoid the sample auto-executing if extracted.
            archive.CreateEntryFromFile(quarantinedFilePath, Path.GetFileName(quarantinedFilePath) + ".bin");
        }

        var record = new SampleSubmissionRecord
        {
            Id = Guid.NewGuid(),
            OriginalFilePath = quarantinedFilePath,
            PackagedArchivePath = archivePath,
            Submitted = false,
            Success = false,
            CreatedAtUtc = DateTime.UtcNow
        };

        using (var scope = scopeFactory.CreateScope())
        {
            var repository = scope.ServiceProvider.GetRequiredService<ISampleSubmissionRepository>();
            await repository.AddAsync(record, ct).ConfigureAwait(false);
        }

        return archivePath;
    }

    public async Task<bool> SubmitAsync(string packagedArchivePath, string submissionUrl, CancellationToken ct = default)
    {
        bool success;
        string? error = null;

        try
        {
            await using var stream = File.OpenRead(packagedArchivePath);
            using var content = new MultipartFormDataContent();
            using var fileContent = new StreamContent(stream);
            fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/zip");
            content.Add(fileContent, "sample", Path.GetFileName(packagedArchivePath));

            using var http = httpClientFactory.CreateClient(ThreatFeeds.ThreatFeedHttpClient.Name);
            using var response = await http.PostAsync(submissionUrl, content, ct).ConfigureAwait(false);
            success = response.IsSuccessStatusCode;
            if (!success) error = $"HTTP {(int)response.StatusCode}";
        }
        catch (Exception ex)
        {
            success = false;
            error = ex.Message;
        }

        try
        {
            using var scope = scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<ISampleSubmissionRepository>();
            await repository.AddAsync(new SampleSubmissionRecord
            {
                Id = Guid.NewGuid(),
                OriginalFilePath = packagedArchivePath,
                PackagedArchivePath = packagedArchivePath,
                SubmittedToUrl = submissionUrl,
                Submitted = true,
                Success = success,
                ErrorMessage = error,
                CreatedAtUtc = DateTime.UtcNow
            }, ct).ConfigureAwait(false);
        }
        catch { }

        return success;
    }
}

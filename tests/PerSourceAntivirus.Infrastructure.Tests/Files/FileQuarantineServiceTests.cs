using FluentAssertions;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Files;

namespace PerSourceAntivirus.Infrastructure.Tests.Files;

public class FileQuarantineServiceTests
{
    [Fact]
    public async Task QuarantineAsync_MovesFileToQuarantineDirectory()
    {
        var sourceDir = Directory.CreateTempSubdirectory().FullName;
        var quarantineDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var filePath = Path.Combine(sourceDir, "evil.ps1");
            await File.WriteAllTextAsync(filePath, "bad content");

            var file = new ScannedFile
            {
                Id = Guid.NewGuid(),
                FilePath = filePath,
                FileName = "evil.ps1",
                SizeBytes = 12,
                Sha256Hash = "aabbcc",
                Entropy = 1.0
            };

            var service = new FileQuarantineService(quarantineDir);
            var quarantinePath = await service.QuarantineAsync(file);

            File.Exists(filePath).Should().BeFalse("original file should be moved");
            File.Exists(quarantinePath).Should().BeTrue("quarantined copy should exist");
            quarantinePath.Should().EndWith(".quarantine");
        }
        finally
        {
            Directory.Delete(sourceDir, recursive: true);
            Directory.Delete(quarantineDir, recursive: true);
        }
    }

    [Fact]
    public async Task RestoreAsync_MovesFileBackToOriginalPath()
    {
        var sourceDir = Directory.CreateTempSubdirectory().FullName;
        var quarantineDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var originalPath = Path.Combine(sourceDir, "evil.ps1");
            await File.WriteAllTextAsync(originalPath, "bad content");

            var fileId = Guid.NewGuid();
            var quarantineFileName = $"{fileId}_evil.ps1.quarantine";
            var quarantinePath = Path.Combine(quarantineDir, quarantineFileName);
            File.Move(originalPath, quarantinePath);

            var file = new ScannedFile
            {
                Id = fileId,
                FilePath = originalPath,
                FileName = "evil.ps1",
                SizeBytes = 12,
                Sha256Hash = "aabbcc",
                Entropy = 1.0,
                IsQuarantined = true,
                QuarantinePath = quarantinePath
            };

            var service = new FileQuarantineService(quarantineDir);
            await service.RestoreAsync(file);

            File.Exists(originalPath).Should().BeTrue("restored file should be back at original path");
            File.Exists(quarantinePath).Should().BeFalse("quarantine copy should be removed");
        }
        finally
        {
            Directory.Delete(sourceDir, recursive: true);
            Directory.Delete(quarantineDir, recursive: true);
        }
    }

    [Fact]
    public async Task RestoreAsync_ThrowsFileNotFoundException_WhenQuarantineFileMissing()
    {
        var quarantineDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var file = new ScannedFile
            {
                Id = Guid.NewGuid(),
                FilePath = Path.Combine(quarantineDir, "nonexistent.txt"),
                FileName = "nonexistent.txt",
                SizeBytes = 0,
                Sha256Hash = "00",
                Entropy = 0,
                IsQuarantined = true,
                QuarantinePath = Path.Combine(quarantineDir, "ghost.quarantine")
            };

            var service = new FileQuarantineService(quarantineDir);
            await Assert.ThrowsAsync<FileNotFoundException>(() => service.RestoreAsync(file));
        }
        finally
        {
            Directory.Delete(quarantineDir, recursive: true);
        }
    }
}

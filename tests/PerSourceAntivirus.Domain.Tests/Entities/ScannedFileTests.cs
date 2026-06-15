using FluentAssertions;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Domain.Tests.Entities;

public class ScannedFileTests
{
    [Fact]
    public void NewScannedFile_DefaultsThreatStatusToUnknown()
    {
        var scannedFile = new ScannedFile
        {
            Id = Guid.NewGuid(),
            FilePath = @"C:\file.txt",
            FileName = "file.txt",
            Sha256Hash = new string('0', 64)
        };

        scannedFile.ThreatStatus.Should().Be(ThreatStatus.Unknown);
    }
}

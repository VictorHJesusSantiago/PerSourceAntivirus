using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Metadata;

namespace PerSourceAntivirus.Infrastructure.Tests.Metadata;

public class FileMetadataAnalyzerTests
{
    private readonly MetadataExtractorAnalyzer _analyzer = new();

    [Fact]
    public void Analyze_ReturnsNull_WhenFileDoesNotExist()
    {
        var result = _analyzer.Analyze(Path.Combine(Path.GetTempPath(), "nonexistent_xyz_abc.jpg"));
        result.Should().BeNull();
    }

    [Fact]
    public void Analyze_ReturnsNull_ForUnsupportedExtensionWithoutAnomalies()
    {
        var path = Path.GetTempFileName(); // .tmp extension, not in supported set, no anomalies
        try
        {
            File.WriteAllText(path, "plain text content with no magic bytes");
            // .tmp has no expected magic bytes and MetadataExtractor won't find metadata → null
            var result = _analyzer.Analyze(path);
            // May be null (nothing found) — should not throw
            result.Should().BeNull();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_DetectsPolyglot_WhenZipMagicInJpegFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.jpg");
        try
        {
            // ZIP magic bytes (PK\x03\x04) written to a .jpg file
            File.WriteAllBytes(path, [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00,
                                      0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.IsPolyglot.Should().BeTrue();
            result.Anomalies.Should().Contain(a => a.Contains("MagicBytes") || a.Contains("EmbeddedSignature"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_DetectsPdfJavaScript_WhenMarkerPresent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pdf");
        try
        {
            // Minimal PDF header + JavaScript action marker
            var content = "%PDF-1.4\n/JavaScript << /S /JavaScript /JS (app.alert('hi')) >>\n";
            File.WriteAllText(path, content);

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.HasJavaScript.Should().BeTrue();
            result.Anomalies.Should().Contain("PdfJavaScript");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_DetectsPdfEmbeddedFiles_WhenMarkerPresent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pdf");
        try
        {
            var content = "%PDF-1.5\n/EmbeddedFile (attachment.exe)\n";
            File.WriteAllText(path, content);

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.HasEmbeddedFiles.Should().BeTrue();
            result.Anomalies.Should().Contain("PdfEmbeddedFiles");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_DetectsPdfAutoAction_WhenOpenActionPresent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pdf");
        try
        {
            var content = "%PDF-1.4\n/OpenAction << /S /Launch /F (calc.exe) >>\n";
            File.WriteAllText(path, content);

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.Anomalies.Should().Contain("PdfAutoAction");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_DetectsEmbeddedPe_InsideJpegBody()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.jpg");
        try
        {
            // Valid JPEG header followed by an MZ (PE) magic at offset 16
            var data = new byte[32];
            data[0] = 0xFF; data[1] = 0xD8; data[2] = 0xFF; // JPEG SOI
            data[16] = 0x4D; data[17] = 0x5A;               // MZ (PE)
            File.WriteAllBytes(path, data);

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.IsPolyglot.Should().BeTrue();
            result.Anomalies.Should().Contain(a => a.Contains("WindowsPE"));
        }
        finally { File.Delete(path); }
    }
}

using FluentAssertions;
using OpenMcdf;
using PerSourceAntivirus.Infrastructure.Office;

namespace PerSourceAntivirus.Infrastructure.Tests.Office;

public class OfficeMacroAnalyzerTests
{
    private readonly OfficeMacroAnalyzer _analyzer = new();

    [Fact]
    public void Analyze_ReturnsNull_ForNonOfficeFile()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "hello world");
            _analyzer.Analyze(path).Should().BeNull();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_ReturnsHasMacrosFalse_ForOle2WithoutVbaStorage()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.doc");
        try
        {
            // Create a valid OLE2 compound file with no VBA storage using OpenMcdf 3.x API
            using (var root = RootStorage.Create(path))
            {
                root.CreateStorage("WordDocument");
            }

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.HasMacros.Should().BeFalse();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_ReturnsNull_ForDocxWithoutVbaProject()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.docm");
        try
        {
            using var zip = System.IO.Compression.ZipFile.Open(
                path, System.IO.Compression.ZipArchiveMode.Create);
            var entry = zip.CreateEntry("word/document.xml");
            using var w = new StreamWriter(entry.Open());
            w.Write("<root/>");

            var result = _analyzer.Analyze(path);
            result.Should().BeNull();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyze_DetectsMacros_WhenVbaStorageContainsModuleStream()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.doc");
        try
        {
            var vbaCode = "Sub AutoOpen()\nShell \"cmd.exe /c whoami\"\nEnd Sub\n";
            var codeBytes = System.Text.Encoding.Default.GetBytes(vbaCode);

            // Uncompressed VBA stream: 0x01 signature + raw-chunk header + code + padding
            var chunk = new byte[2 + 4096];
            chunk[0] = 0xFF; chunk[1] = 0x3F; // raw-chunk header (isCompressed=0)
            Array.Copy(codeBytes, 0, chunk, 2, Math.Min(codeBytes.Length, 4096));

            var streamData = new byte[1 + chunk.Length];
            streamData[0] = 0x01; // compression signature
            Array.Copy(chunk, 0, streamData, 1, chunk.Length);

            using (var root = RootStorage.Create(path))
            {
                var vbaStorage = root.CreateStorage("VBA");
                using var moduleStream = vbaStorage.CreateStream("Module1");
                moduleStream.Write(streamData, 0, streamData.Length);
            }

            var result = _analyzer.Analyze(path);

            result.Should().NotBeNull();
            result!.HasMacros.Should().BeTrue();
            result.HasAutoExec.Should().BeTrue();
            result.HasProcessExecution.Should().BeTrue();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void VbaDecompressor_DoesNotThrow_OnArbitraryBytes()
    {
        var act = () => VbaDecompressor.Decompress([0x01, 0xFF, 0x3F, 0x41, 0x42, 0x43]);
        act.Should().NotThrow();
    }

    [Fact]
    public void VbaDecompressor_ExtractsPrintableText_FromRawBytes()
    {
        var bytes = "Hello World\x01\x02"u8.ToArray();
        var text = VbaDecompressor.ExtractPrintableText(bytes);
        text.Should().Contain("Hello World");
    }
}

using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Pe;

namespace PerSourceAntivirus.Infrastructure.Tests.Pe;

public class PeAnalyzerTests
{
    [Fact]
    public void Analyze_ReturnsNull_ForNonPeFile()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            File.WriteAllText(filePath, "this is a plain text file, not a PE");
            var analyzer = new PeAnalyzer();

            var result = analyzer.Analyze(filePath);

            result.Should().BeNull();
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public void Analyze_ReturnsResult_ForManagedAssembly()
    {
        var assemblyPath = typeof(PeAnalyzer).Assembly.Location;
        var analyzer = new PeAnalyzer();

        var result = analyzer.Analyze(assemblyPath);

        result.Should().NotBeNull();
        result!.IsDotNet.Should().BeTrue();
        result.Sections.Should().NotBeEmpty();
    }

    [Fact]
    public void Analyze_ReturnsNull_ForEmptyFile()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(filePath, []);
            var analyzer = new PeAnalyzer();

            var result = analyzer.Analyze(filePath);

            result.Should().BeNull();
        }
        finally
        {
            File.Delete(filePath);
        }
    }
}

using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Pe;

namespace PerSourceAntivirus.Infrastructure.Tests.Pe;

public class OnnxPeMlClassifierTests
{
    [Fact]
    public void Classify_ReturnsHeuristicVersion_WhenNoModelFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            using var classifier = new OnnxPeMlClassifier(tempDir);

            classifier.ModelVersion.Should().Be("heuristic-v1");
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Classify_ReturnsNotPe_ForNonPeFile()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            File.WriteAllText(filePath, "this is plain text, not a PE file");
            using var classifier = new OnnxPeMlClassifier(Path.GetTempPath());

            var result = classifier.Classify(filePath);

            result.Classification.Should().Be("NotPe");
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public void Classify_ReturnsCleanOrSuspicious_ForDotNetAssembly()
    {
        var assemblyPath = typeof(OnnxPeMlClassifier).Assembly.Location;
        using var classifier = new OnnxPeMlClassifier(Path.GetTempPath());

        var result = classifier.Classify(assemblyPath);

        result.Classification.Should().BeOneOf("Clean", "Suspicious");
        result.MaliciousProbability.Should().BeGreaterOrEqualTo(0f);
    }

    [Fact]
    public void Classify_ReturnsNonNegativeProbability_ForAnyPe()
    {
        var assemblyPath = typeof(OnnxPeMlClassifier).Assembly.Location;
        using var classifier = new OnnxPeMlClassifier(Path.GetTempPath());

        var result = classifier.Classify(assemblyPath);

        result.MaliciousProbability.Should().BeGreaterOrEqualTo(0f);
        result.MaliciousProbability.Should().BeLessOrEqualTo(1f);
    }
}

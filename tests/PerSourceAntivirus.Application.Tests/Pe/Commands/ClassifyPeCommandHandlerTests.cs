using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Pe.Commands.ClassifyPe;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Pe.Commands;

public class ClassifyPeCommandHandlerTests
{
    private static ClassifyPeCommandHandler Build(IPeMlClassifier? classifier = null, IPeMlPredictionRepository? repo = null)
    {
        classifier ??= Substitute.For<IPeMlClassifier>();
        repo ??= Substitute.For<IPeMlPredictionRepository>();
        return new ClassifyPeCommandHandler(classifier, repo);
    }

    [Fact]
    public async Task Handle_ReturnsUnknown_WhenFileDoesNotExist()
    {
        var classifier = Substitute.For<IPeMlClassifier>();
        classifier.ModelVersion.Returns("heuristic-v1");

        var result = await Build(classifier).Handle(
            new ClassifyPeCommand(@"C:\nonexistent_file_xyz.exe"),
            CancellationToken.None);

        result.Classification.Should().Be("Unknown");
        result.IsPeFile.Should().BeFalse();
    }

    [Fact]
    public async Task Handle_ClassifiesMalicious_AndPersists()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, new byte[] { 0x4D, 0x5A, 0x90, 0x00 }); // MZ header

            var classifier = Substitute.For<IPeMlClassifier>();
            classifier.ModelVersion.Returns("heuristic-v1");
            classifier.Classify(tmp).Returns(new PeMlResult(0.85f, "Malicious", "heuristic-v1", [0.85f], ["score"]));

            var repo = Substitute.For<IPeMlPredictionRepository>();

            var result = await Build(classifier, repo).Handle(
                new ClassifyPeCommand(tmp),
                CancellationToken.None);

            result.Classification.Should().Be("Malicious");
            result.MaliciousProbability.Should().BeApproximately(0.85f, 0.001f);
            result.IsPeFile.Should().BeTrue();
            await repo.Received(1).AddAsync(Arg.Any<PeMlPrediction>(), Arg.Any<CancellationToken>());
        }
        finally { File.Delete(tmp); }
    }

    [Fact]
    public async Task Handle_ReturnsNotPe_AndSkipsPersistence_ForNonPeFile()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmp, "not a PE file");

            var classifier = Substitute.For<IPeMlClassifier>();
            classifier.ModelVersion.Returns("heuristic-v1");
            classifier.Classify(tmp).Returns(new PeMlResult(0f, "NotPe", "heuristic-v1", [], []));

            var repo = Substitute.For<IPeMlPredictionRepository>();

            var result = await Build(classifier, repo).Handle(
                new ClassifyPeCommand(tmp),
                CancellationToken.None);

            result.Classification.Should().Be("NotPe");
            result.IsPeFile.Should().BeFalse();
            await repo.DidNotReceive().AddAsync(Arg.Any<PeMlPrediction>(), Arg.Any<CancellationToken>());
        }
        finally { File.Delete(tmp); }
    }
}

using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Pe.Queries.GetMlPredictions;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Pe.Queries;

public class GetMlPredictionsQueryHandlerTests
{
    private static GetMlPredictionsQueryHandler Build(IPeMlPredictionRepository? repo = null)
    {
        repo ??= Substitute.For<IPeMlPredictionRepository>();
        return new GetMlPredictionsQueryHandler(repo);
    }

    [Fact]
    public async Task Handle_ReturnsAllPredictions_WhenNoFilter()
    {
        var repo = Substitute.For<IPeMlPredictionRepository>();
        var predictions = new List<PeMlPrediction>
        {
            new() { FilePath = "a.exe", Classification = "Clean",     MaliciousProbability = 0.1f, ModelVersion = "v1" },
            new() { FilePath = "b.exe", Classification = "Malicious", MaliciousProbability = 0.9f, ModelVersion = "v1" },
        };
        repo.GetAllAsync(null, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<PeMlPrediction>>(predictions));

        var result = await Build(repo).Handle(new GetMlPredictionsQuery(), CancellationToken.None);

        result.Should().HaveCount(2);
    }

    [Fact]
    public async Task Handle_PassesClassificationFilter_ToRepository()
    {
        var repo = Substitute.For<IPeMlPredictionRepository>();
        repo.GetAllAsync("Malicious", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<PeMlPrediction>>([]));

        await Build(repo).Handle(new GetMlPredictionsQuery("Malicious"), CancellationToken.None);

        await repo.Received(1).GetAllAsync("Malicious", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsEmpty_WhenRepositoryIsEmpty()
    {
        var repo = Substitute.For<IPeMlPredictionRepository>();
        repo.GetAllAsync(Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<PeMlPrediction>>([]));

        var result = await Build(repo).Handle(new GetMlPredictionsQuery(), CancellationToken.None);

        result.Should().BeEmpty();
    }
}

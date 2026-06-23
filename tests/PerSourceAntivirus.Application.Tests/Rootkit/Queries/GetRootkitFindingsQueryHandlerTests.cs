using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Rootkit.Queries.GetRootkitFindings;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Tests.Rootkit.Queries;

public class GetRootkitFindingsQueryHandlerTests
{
    private static GetRootkitFindingsQueryHandler Build(IRootkitFindingRepository? repo = null)
    {
        repo ??= Substitute.For<IRootkitFindingRepository>();
        return new GetRootkitFindingsQueryHandler(repo);
    }

    [Fact]
    public async Task Handle_DelegatesToRepoAndReturnsList()
    {
        var repo = Substitute.For<IRootkitFindingRepository>();
        var findings = new List<RootkitFinding>
        {
            new() { Id = 1, FindingType = RootkitFindingType.DkomManipulation, Description = "DKOM manipulation", Severity = "High" },
            new() { Id = 2, FindingType = RootkitFindingType.HiddenProcess, Description = "Hidden process", Severity = "Critical" }
        };
        repo.GetAllAsync(Arg.Any<CancellationToken>()).Returns(findings);

        var result = await Build(repo).Handle(new GetRootkitFindingsQuery(), CancellationToken.None);

        result.Should().BeEquivalentTo(findings);
        await repo.Received(1).GetAllAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsEmptyList_WhenRepoIsEmpty()
    {
        var repo = Substitute.For<IRootkitFindingRepository>();
        repo.GetAllAsync(Arg.Any<CancellationToken>()).Returns(new List<RootkitFinding>());

        var result = await Build(repo).Handle(new GetRootkitFindingsQuery(), CancellationToken.None);

        result.Should().BeEmpty();
    }
}

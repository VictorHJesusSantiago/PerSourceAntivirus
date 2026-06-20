using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IEventHistoryService
{
    Task RecordProcessCreationAsync(ProcessCreationEvent evt, CancellationToken ct = default);
    Task RecordFileActivityAsync(FileActivityEvent evt, CancellationToken ct = default);
    Task RecordRegistryActivityAsync(RegistryActivityEvent evt, CancellationToken ct = default);
    event EventHandler<ProcessCreationEventArgs> ProcessCreated;
    event EventHandler<FileActivityEventArgs> FileActivity;
    event EventHandler<RegistryActivityEventArgs> RegistryActivity;
}

public record ProcessCreationEventArgs(ProcessCreationEvent Event);
public record FileActivityEventArgs(FileActivityEvent Event);
public record RegistryActivityEventArgs(RegistryActivityEvent Event);

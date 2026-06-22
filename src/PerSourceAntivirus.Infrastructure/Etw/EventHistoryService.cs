using System.Runtime.Versioning;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Etw;

[SupportedOSPlatform("windows")]
public sealed class EventHistoryService : IEventHistoryService
{
    private static readonly Guid KernelProcessGuid  = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
    private static readonly Guid KernelFileGuid     = new("EDD08927-9CC4-4E65-B970-C2560FB5C289");
    private static readonly Guid KernelRegistryGuid = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");

    private const string SessionName = "PerSourceAntivirusEventHistory";

    private readonly IProcessCreationEventRepository  _processRepo;
    private readonly IFileActivityEventRepository     _fileRepo;
    private readonly IRegistryActivityEventRepository _registryRepo;

    public event EventHandler<ProcessCreationEventArgs>? ProcessCreated;
    public event EventHandler<FileActivityEventArgs>?    FileActivity;
    public event EventHandler<RegistryActivityEventArgs>? RegistryActivity;

    public EventHistoryService(
        IProcessCreationEventRepository processRepo,
        IFileActivityEventRepository fileRepo,
        IRegistryActivityEventRepository registryRepo)
    {
        _processRepo  = processRepo;
        _fileRepo     = fileRepo;
        _registryRepo = registryRepo;
    }

    public async Task RecordProcessCreationAsync(ProcessCreationEvent evt, CancellationToken ct = default)
    {
        await _processRepo.AddAsync(evt, ct);
        ProcessCreated?.Invoke(this, new ProcessCreationEventArgs(evt));
    }

    public async Task RecordFileActivityAsync(FileActivityEvent evt, CancellationToken ct = default)
    {
        await _fileRepo.AddAsync(evt, ct);
        FileActivity?.Invoke(this, new FileActivityEventArgs(evt));
    }

    public async Task RecordRegistryActivityAsync(RegistryActivityEvent evt, CancellationToken ct = default)
    {
        await _registryRepo.AddAsync(evt, ct);
        RegistryActivity?.Invoke(this, new RegistryActivityEventArgs(evt));
    }

    public void StartWatching(CancellationToken ct)
    {
        var processChannel  = Channel.CreateUnbounded<ProcessCreationEvent>(new UnboundedChannelOptions { SingleReader = true });
        var fileChannel     = Channel.CreateUnbounded<FileActivityEvent>(new UnboundedChannelOptions { SingleReader = true });
        var registryChannel = Channel.CreateUnbounded<RegistryActivityEvent>(new UnboundedChannelOptions { SingleReader = true });

        Task.Run(() =>
        {
            try
            {
                using var session = new TraceEventSession(SessionName);
                ct.Register(() => { try { session.Stop(); } catch { } });

                session.EnableProvider(KernelProcessGuid,  TraceEventLevel.Informational);
                session.EnableProvider(KernelFileGuid,     TraceEventLevel.Informational);
                session.EnableProvider(KernelRegistryGuid, TraceEventLevel.Informational);

                session.Source.Dynamic.All += data =>
                {
                    try
                    {
                        var providerGuid = data.ProviderGuid;

                        if (providerGuid == KernelProcessGuid && data.ID == (TraceEventID)1)
                        {
                            var imagePath    = data.PayloadStringByName("ImageName") ?? string.Empty;
                            var commandLine  = data.PayloadStringByName("CommandLine") ?? string.Empty;
                            var userName     = data.PayloadStringByName("UserSID") ?? string.Empty;
                            var parentPid    = (int)(data.PayloadByName("ParentProcessID") ?? 0);
                            var evt = new ProcessCreationEvent
                            {
                                Id              = Guid.NewGuid(),
                                ImagePath       = imagePath,
                                FileName        = Path.GetFileName(imagePath),
                                CommandLine     = commandLine,
                                Sha256Hash      = string.Empty,
                                ProcessId       = data.ProcessID,
                                ParentProcessId = parentPid,
                                ParentImagePath = string.Empty,
                                UserName        = userName,
                                IntegrityLevel  = string.Empty,
                                IsSuspicious    = false,
                                CreatedAtUtc    = DateTime.UtcNow,
                            };
                            processChannel.Writer.TryWrite(evt);
                        }
                        else if (providerGuid == KernelFileGuid && (data.ID == (TraceEventID)12 || data.ID == (TraceEventID)14 || data.ID == (TraceEventID)15))
                        {
                            var filePath = data.PayloadStringByName("FileName") ?? string.Empty;
                            var operation = data.ID == (TraceEventID)12 ? "Create" : data.ID == (TraceEventID)14 ? "SetInfo" : "Delete";
                            var evt = new FileActivityEvent
                            {
                                Id          = Guid.NewGuid(),
                                ProcessId   = data.ProcessID,
                                ProcessName = data.ProcessName,
                                ImagePath   = string.Empty,
                                FilePath    = filePath,
                                FileName    = Path.GetFileName(filePath),
                                Operation   = operation,
                                FileSize    = 0,
                                Sha256Hash  = string.Empty,
                                IsSuspicious = false,
                                OccurredAtUtc = DateTime.UtcNow,
                            };
                            fileChannel.Writer.TryWrite(evt);
                        }
                        else if (providerGuid == KernelRegistryGuid && data.ID >= (TraceEventID)1 && data.ID <= (TraceEventID)4)
                        {
                            var keyPath   = data.PayloadStringByName("KeyName") ?? string.Empty;
                            var valueName = data.PayloadStringByName("ValueName") ?? string.Empty;
                            var operation = data.ID switch
                            {
                                (TraceEventID)1 => "Create",
                                (TraceEventID)2 => "Open",
                                (TraceEventID)3 => "SetValue",
                                (TraceEventID)4 => "DeleteKey",
                                _               => "Unknown",
                            };
                            var evt = new RegistryActivityEvent
                            {
                                Id          = Guid.NewGuid(),
                                ProcessId   = data.ProcessID,
                                ProcessName = data.ProcessName,
                                KeyPath     = keyPath,
                                ValueName   = valueName,
                                Operation   = operation,
                                OldData     = string.Empty,
                                NewData     = string.Empty,
                                IsSuspicious = false,
                                OccurredAtUtc = DateTime.UtcNow,
                            };
                            registryChannel.Writer.TryWrite(evt);
                        }
                    }
                    catch { }
                };

                session.Source.Process();
            }
            catch { }
            finally
            {
                processChannel.Writer.TryComplete();
                fileChannel.Writer.TryComplete();
                registryChannel.Writer.TryComplete();
            }
        }, CancellationToken.None);

        Task.Run(async () =>
        {
            await foreach (var evt in processChannel.Reader.ReadAllAsync(ct))
            {
                try { ProcessCreated?.Invoke(this, new ProcessCreationEventArgs(evt)); } catch { }
            }
        }, ct);

        Task.Run(async () =>
        {
            await foreach (var evt in fileChannel.Reader.ReadAllAsync(ct))
            {
                try { FileActivity?.Invoke(this, new FileActivityEventArgs(evt)); } catch { }
            }
        }, ct);

        Task.Run(async () =>
        {
            await foreach (var evt in registryChannel.Reader.ReadAllAsync(ct))
            {
                try { RegistryActivity?.Invoke(this, new RegistryActivityEventArgs(evt)); } catch { }
            }
        }, ct);
    }
}

using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Siem.Commands.ExportSiemBatch;

public class ExportSiemBatchCommandHandler(
    ISiemExporter exporter,
    IScannedFileRepository scannedFileRepo,
    INetworkConnectionEventRepository networkRepo,
    IRansomwareAlertRepository ransomwareRepo,
    IWfpBlockRepository wfpRepo)
    : IRequestHandler<ExportSiemBatchCommand, int>
{
    public async Task<int> Handle(ExportSiemBatchCommand request, CancellationToken cancellationToken)
    {
        if (!exporter.IsEnabled)
            return 0;

        var payloads = new List<SiemEventPayload>();

        // Scan results with YARA matches
        var scannedFiles = await scannedFileRepo.GetAllAsync(cancellationToken);
        foreach (var file in scannedFiles.Take(request.MaxEvents))
        {
            foreach (var match in file.YaraMatches)
            {
                var isMalicious = match.Tags.Contains("malicious", StringComparison.OrdinalIgnoreCase);
                var severity = isMalicious ? 9 : 5;
                payloads.Add(new SiemEventPayload(
                    DeviceVendor: "PerSourceAntivirus",
                    DeviceProduct: "PSAV",
                    DeviceVersion: "1.0",
                    SignatureId: 1001,
                    Name: $"YARA rule matched: {match.RuleIdentifier}",
                    Severity: severity,
                    OccurredAtUtc: file.ScannedAtUtc,
                    SourceIp: null,
                    DestinationIp: null,
                    FileName: file.FileName,
                    UserName: null,
                    Extensions: new Dictionary<string, string>
                    {
                        ["ruleId"] = match.RuleIdentifier,
                        ["tags"] = match.Tags,
                        ["filePath"] = file.FilePath,
                        ["sha256"] = file.Sha256Hash
                    }
                ));
            }
        }

        // Network connection events (blocked)
        var networkEvents = await networkRepo.GetAllAsync(onlyBlocklisted: true, cancellationToken: cancellationToken);
        foreach (var evt in networkEvents.Take(request.MaxEvents))
        {
            payloads.Add(new SiemEventPayload(
                DeviceVendor: "PerSourceAntivirus",
                DeviceProduct: "PSAV",
                DeviceVersion: "1.0",
                SignatureId: 2001,
                Name: "Blocked IP connection",
                Severity: 7,
                OccurredAtUtc: evt.CapturedAtUtc,
                SourceIp: evt.SourceAddress,
                DestinationIp: evt.DestinationAddress,
                FileName: null,
                UserName: null,
                Extensions: new Dictionary<string, string>
                {
                    ["protocol"] = evt.Protocol.ToString(),
                    ["srcPort"] = evt.SourcePort.ToString(),
                    ["dstPort"] = evt.DestinationPort.ToString(),
                    ["blockReason"] = evt.BlocklistReason ?? string.Empty
                }
            ));
        }

        // Ransomware alerts
        var ransomwareAlerts = await ransomwareRepo.GetAllAsync(onlyCritical: false, ct: cancellationToken);
        foreach (var alert in ransomwareAlerts.Take(request.MaxEvents))
        {
            var severity = alert.Severity switch
            {
                RansomwareSeverity.Critical => 10,
                RansomwareSeverity.High => 8,
                RansomwareSeverity.Warning => 6,
                _ => 5
            };
            payloads.Add(new SiemEventPayload(
                DeviceVendor: "PerSourceAntivirus",
                DeviceProduct: "PSAV",
                DeviceVersion: "1.0",
                SignatureId: 3001,
                Name: $"Ransomware alert: {alert.EventType}",
                Severity: severity,
                OccurredAtUtc: alert.DetectedAtUtc,
                SourceIp: null,
                DestinationIp: null,
                FileName: Path.GetFileName(alert.FilePath),
                UserName: null,
                Extensions: new Dictionary<string, string>
                {
                    ["eventType"] = alert.EventType.ToString(),
                    ["severity"] = alert.Severity.ToString(),
                    ["filePath"] = alert.FilePath,
                    ["detail"] = alert.Detail,
                    ["processId"] = alert.ProcessId?.ToString() ?? string.Empty,
                    ["processName"] = alert.ProcessName ?? string.Empty
                }
            ));
        }

        // WFP blocks triggered
        var wfpBlocks = await wfpRepo.GetAllAsync(cancellationToken);
        foreach (var block in wfpBlocks.Where(b => b.IsActive).Take(request.MaxEvents))
        {
            payloads.Add(new SiemEventPayload(
                DeviceVendor: "PerSourceAntivirus",
                DeviceProduct: "PSAV",
                DeviceVersion: "1.0",
                SignatureId: 4001,
                Name: "WFP block triggered",
                Severity: 8,
                OccurredAtUtc: block.AddedAtUtc,
                SourceIp: null,
                DestinationIp: block.IpAddress,
                FileName: null,
                UserName: null,
                Extensions: new Dictionary<string, string>
                {
                    ["ipAddress"] = block.IpAddress,
                    ["reason"] = block.Reason,
                    ["filterIdOutbound"] = block.FilterIdOutboundV4.ToString(),
                    ["filterIdInbound"] = block.FilterIdInboundV4.ToString()
                }
            ));
        }

        var batch = payloads.Take(request.MaxEvents).ToList();
        if (batch.Count > 0)
            await exporter.ExportBatchAsync(batch, cancellationToken);

        return batch.Count;
    }
}

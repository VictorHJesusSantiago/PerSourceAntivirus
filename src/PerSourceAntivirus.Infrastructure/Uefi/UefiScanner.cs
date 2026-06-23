using System.Runtime.InteropServices;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Uefi;

public class UefiScanner : IUefiScanner
{
    private const uint AcpiProvider = 0x41435049; // 'ACPI'
    private const uint RsmbProvider = 0x52534D42; // 'RSMB'

    private static readonly (string Name, string Description, byte[] Signature)[] KnownSignatures =
    [
        ("LoJax", "Absolute LoJax UEFI rootkit DXE module GUID",
            new byte[] { 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x00, 0x00 }),
        ("CosmicStrand", "CosmicStrand UEFI rootkit hook pattern",
            new byte[] { 0x83, 0xEC, 0x08, 0x53, 0x56, 0x57, 0x8B, 0xF1, 0x8B, 0xDA }),
        ("MosaicRegressor", "MosaicRegressor NautilusBoot module marker",
            new byte[] { 0x4E, 0x61, 0x75, 0x74, 0x69, 0x6C, 0x75, 0x73, 0x42, 0x6F, 0x6F, 0x74 }),
        ("SuspiciousResetSystem", "Potentially hooked UEFI ResetSystem runtime service",
            new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }),
    ];

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(
        uint FirmwareTableProviderSignature,
        uint FirmwareTableID,
        [Out] byte[]? pFirmwareTableBuffer,
        uint BufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint EnumSystemFirmwareTables(
        uint FirmwareTableProviderSignature,
        [Out] byte[]? pFirmwareTableEnumBuffer,
        uint BufferSize);

    public Task<IReadOnlyList<UefiFinding>> ScanAsync(CancellationToken ct = default)
    {
        var findings = new List<UefiFinding>();
        findings.AddRange(ScanProvider(AcpiProvider, "ACPI", ct));
        findings.AddRange(ScanProvider(RsmbProvider, "RSMB", ct));
        return Task.FromResult<IReadOnlyList<UefiFinding>>(findings);
    }

    private List<UefiFinding> ScanProvider(uint provider, string providerName, CancellationToken ct)
    {
        var findings = new List<UefiFinding>();

        var enumSize = EnumSystemFirmwareTables(provider, null, 0);
        if (enumSize == 0) return findings;

        var enumBuffer = new byte[enumSize];
        if (EnumSystemFirmwareTables(provider, enumBuffer, enumSize) == 0) return findings;

        var tableCount = (int)enumSize / 4;
        for (var i = 0; i < tableCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            var tableId = BitConverter.ToUInt32(enumBuffer, i * 4);
            var tableName = TableIdToString(tableId);

            var dataSize = GetSystemFirmwareTable(provider, tableId, null, 0);
            if (dataSize == 0) continue;

            var tableData = new byte[dataSize];
            if (GetSystemFirmwareTable(provider, tableId, tableData, dataSize) == 0) continue;

            foreach (var (sigName, description, signature) in KnownSignatures)
            {
                var offset = IndexOf(tableData, signature);
                if (offset >= 0)
                {
                    findings.Add(new UefiFinding
                    {
                        DetectedAtUtc = DateTime.UtcNow,
                        TableName = $"{providerName}/{tableName}",
                        SignatureName = sigName,
                        Description = description,
                        MatchOffset = offset
                    });
                }
            }
        }

        return findings;
    }

    private static string TableIdToString(uint tableId)
    {
        var bytes = BitConverter.GetBytes(tableId);
        var sb = new StringBuilder(4);
        foreach (var b in bytes)
            sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '?');
        return sb.ToString();
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}

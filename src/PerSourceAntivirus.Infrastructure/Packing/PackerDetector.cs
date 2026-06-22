// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IPackerDetector, PackerDetector>();

using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Packing;

public class PackerDetector : IPackerDetector
{
    private const int SignatureReadSize = 512;
    private const int UpxTimeoutMs = 10_000;

    public async Task<PackerDetectionResult> DetectAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
        {
            return new PackerDetectionResult("None", false, false, null);
        }

        byte[] header;
        try
        {
            header = await ReadHeaderAsync(filePath, ct);
        }
        catch
        {
            return new PackerDetectionResult("None", false, false, null);
        }

        var sectionNames = ReadPeSectionNames(header);
        string packerName = DetectPacker(header, sectionNames);

        if (packerName == "None")
        {
            return new PackerDetectionResult("None", false, false, null);
        }

        // Attempt UPX unpacking
        if (packerName == "UPX")
        {
            var (unpacked, tempPath) = await TryUnpackUpxAsync(filePath, ct);
            return new PackerDetectionResult("UPX", true, unpacked, tempPath);
        }

        return new PackerDetectionResult(packerName, true, false, null);
    }

    // ────────────────────────────────────────────────────────────
    // Packer detection
    // ────────────────────────────────────────────────────────────

    private static string DetectPacker(byte[] header, IReadOnlyList<string> sectionNames)
    {
        // UPX: "UPX!" magic or UPX0/UPX1 section names
        if (ContainsSignature(header, "UPX!"u8)
            || sectionNames.Any(n => n.Equals("UPX0", StringComparison.OrdinalIgnoreCase)
                                  || n.Equals("UPX1", StringComparison.OrdinalIgnoreCase)))
        {
            return "UPX";
        }

        // MPRESS
        if (ContainsSignature(header, "MPRESS1"u8) || ContainsSignature(header, "MPRESS2"u8))
        {
            return "MPRESS";
        }

        // ASPack: "aSjX" at PE header + 0x28
        if (HasAspAckSignature(header))
        {
            return "ASPack";
        }

        // PECompact: section name ".pec" or ".pec2"
        if (sectionNames.Any(n => n.Equals(".pec", StringComparison.OrdinalIgnoreCase)
                               || n.Equals(".pec2", StringComparison.OrdinalIgnoreCase)))
        {
            return "PECompact";
        }

        // Themida / WinLicense
        if (sectionNames.Any(n => n.Equals(".themida", StringComparison.OrdinalIgnoreCase)
                               || n.Equals(".winlicense", StringComparison.OrdinalIgnoreCase)))
        {
            return "Themida";
        }

        // VMProtect
        if (sectionNames.Any(n => n.Equals(".vmp0", StringComparison.OrdinalIgnoreCase)
                               || n.Equals(".vmp1", StringComparison.OrdinalIgnoreCase)))
        {
            return "VMProtect";
        }

        return "None";
    }

    private static bool HasAspAckSignature(byte[] header)
    {
        // Offset to COFF/PE header is at 0x3C (4-byte LE)
        if (header.Length < 0x40)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(header, 0x3C);
        int checkOffset = peOffset + 0x28;

        if (checkOffset + 4 > header.Length)
        {
            return false;
        }

        // "aSjX"
        return header[checkOffset] == (byte)'a'
            && header[checkOffset + 1] == (byte)'S'
            && header[checkOffset + 2] == (byte)'j'
            && header[checkOffset + 3] == (byte)'X';
    }

    // ────────────────────────────────────────────────────────────
    // PE section name parsing
    // ────────────────────────────────────────────────────────────

    private static IReadOnlyList<string> ReadPeSectionNames(byte[] header)
    {
        var names = new List<string>();

        try
        {
            // MZ header check
            if (header.Length < 0x40 || header[0] != (byte)'M' || header[1] != (byte)'Z')
            {
                return names;
            }

            int peOffset = BitConverter.ToInt32(header, 0x3C);

            // Validate PE signature "PE\0\0"
            if (peOffset + 4 > header.Length
                || header[peOffset] != (byte)'P'
                || header[peOffset + 1] != (byte)'E'
                || header[peOffset + 2] != 0
                || header[peOffset + 3] != 0)
            {
                return names;
            }

            // COFF header: NumberOfSections at PE+6 (2 bytes)
            if (peOffset + 8 > header.Length)
            {
                return names;
            }

            ushort numberOfSections = BitConverter.ToUInt16(header, peOffset + 6);

            // SizeOfOptionalHeader at PE+20 (2 bytes)
            if (peOffset + 22 > header.Length)
            {
                return names;
            }

            ushort optionalHeaderSize = BitConverter.ToUInt16(header, peOffset + 20);

            // Section table starts at: PE offset + 24 (COFF header size) + optional header size
            int sectionTableOffset = peOffset + 24 + optionalHeaderSize;

            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionTableOffset + i * 40;

                if (sectionOffset + 8 > header.Length)
                {
                    break;
                }

                // Section name: 8 bytes, null-padded ASCII
                string name = ReadNullPaddedAscii(header, sectionOffset, 8);
                if (!string.IsNullOrEmpty(name))
                {
                    names.Add(name);
                }
            }
        }
        catch
        {
            // Malformed PE — return whatever we collected
        }

        return names;
    }

    private static string ReadNullPaddedAscii(byte[] buffer, int offset, int maxLen)
    {
        var sb = new StringBuilder(maxLen);
        for (int i = 0; i < maxLen && offset + i < buffer.Length; i++)
        {
            byte b = buffer[offset + i];
            if (b == 0)
            {
                break;
            }
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    // ────────────────────────────────────────────────────────────
    // UPX unpacking
    // ────────────────────────────────────────────────────────────

    private static async Task<(bool success, string? tempPath)> TryUnpackUpxAsync(
        string filePath,
        CancellationToken ct)
    {
        string? upxPath = FindUpxOnPath();
        if (upxPath is null)
        {
            return (false, null);
        }

        string tempPath = Path.Combine(Path.GetTempPath(), $"unpacked_{Guid.NewGuid():N}.bin");

        try
        {
            using var timeoutCts = new CancellationTokenSource(UpxTimeoutMs);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = upxPath,
                Arguments = $"-d -o \"{tempPath}\" \"{filePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = new System.Diagnostics.Process { StartInfo = psi };
            process.Start();

            await process.WaitForExitAsync(linkedCts.Token);

            if (process.ExitCode == 0 && File.Exists(tempPath))
            {
                return (true, tempPath);
            }

            // Clean up failed temp file
            TryDeleteFile(tempPath);
            return (false, null);
        }
        catch
        {
            TryDeleteFile(tempPath);
            return (false, null);
        }
    }

    private static string? FindUpxOnPath()
    {
        string[] candidates = OperatingSystem.IsWindows()
            ? ["upx.exe", "upx"]
            : ["upx"];

        string? pathVar = Environment.GetEnvironmentVariable("PATH");
        if (pathVar is null)
        {
            return null;
        }

        char separator = OperatingSystem.IsWindows() ? ';' : ':';

        foreach (string dir in pathVar.Split(separator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (string candidate in candidates)
            {
                string full = Path.Combine(dir.Trim(), candidate);
                if (File.Exists(full))
                {
                    return full;
                }
            }
        }

        return null;
    }

    // ────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────

    private static async Task<byte[]> ReadHeaderAsync(string filePath, CancellationToken ct)
    {
        await using var stream = new FileStream(
            filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, useAsync: true);

        int toRead = (int)Math.Min(SignatureReadSize, stream.Length);
        var buffer = new byte[toRead];
        int bytesRead = 0;

        while (bytesRead < toRead)
        {
            int chunk = await stream.ReadAsync(buffer.AsMemory(bytesRead, toRead - bytesRead), ct);
            if (chunk == 0)
            {
                break;
            }
            bytesRead += chunk;
        }

        if (bytesRead < toRead)
        {
            Array.Resize(ref buffer, bytesRead);
        }

        return buffer;
    }

    private static bool ContainsSignature(byte[] buffer, ReadOnlySpan<byte> signature)
    {
        if (signature.Length == 0 || buffer.Length < signature.Length)
        {
            return false;
        }

        for (int i = 0; i <= buffer.Length - signature.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < signature.Length; j++)
            {
                if (buffer[i + j] != signature[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return true;
            }
        }

        return false;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup
        }
    }
}

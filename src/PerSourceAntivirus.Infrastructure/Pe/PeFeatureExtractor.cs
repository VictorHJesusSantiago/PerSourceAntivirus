using PeNet;
using PerSourceAntivirus.Infrastructure.Common;

namespace PerSourceAntivirus.Infrastructure.Pe;

public static class PeFeatureExtractor
{
    public static readonly string[] FeatureNames =
    [
        "file_size_kb",
        "num_sections",
        "avg_section_entropy",
        "max_section_entropy",
        "min_section_entropy",
        "std_section_entropy",
        "num_high_entropy_sections",
        "is_64bit",
        "is_dll",
        "is_dotnet",
        "is_signed",
        "has_tls",
        "has_debug",
        "has_resources",
        "has_overlay",
        "num_imports",
        "num_exports",
        "num_suspicious_imports",
        "import_hash_norm",
        "ratio_code_to_file",
        "ratio_data_to_file",
        "entry_point_norm",
        "num_directories",
        "characteristics_norm",
        "subsystem",
        "major_os_version",
        "major_linker_version",
        "optional_header_size_norm",
        "num_anomalies",
        "timestamp_norm",
    ];

    private static readonly string[] SuspiciousApis =
    [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
    ];

    public static float[]? Extract(string filePath)
    {
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists) return null;

            if (!HasMzHeader(filePath)) return null;

            PeFile pe;
            try { pe = new PeFile(filePath); }
            catch { return null; }

            if (pe.ImageNtHeaders is null) return null;

            var opt = pe.ImageNtHeaders.OptionalHeader;
            var fh  = pe.ImageNtHeaders.FileHeader;

            var sections = (pe.ImageSectionHeaders ?? []).ToList();
            var entropies = sections
                .Select(s => (float)ShannonEntropy.Calculate(s.ToArray()))
                .ToList();

            var numSections = (float)sections.Count;
            var avgEntropy  = entropies.Count > 0 ? entropies.Average() : 0f;
            var maxEntropy  = entropies.Count > 0 ? entropies.Max() : 0f;
            var minEntropy  = entropies.Count > 0 ? entropies.Min() : 0f;
            var stdEntropy  = StdDev(entropies);
            var highEntropySections = (float)entropies.Count(e => e > 7.0f);

            var imports   = pe.ImportedFunctions ?? [];
            var exports   = pe.ExportedFunctions ?? [];
            var numImports = (float)imports.Length;
            var numExports = (float)exports.Length;

            var suspCount = (float)imports
                .Where(i => i.Name is not null && SuspiciousApis.Contains(i.Name, StringComparer.OrdinalIgnoreCase))
                .Select(i => i.Name!)
                .Distinct()
                .Count();

            var importHash = ComputeImportHashNorm(imports);

            var fileSizeBytes = (float)info.Length;
            var codeSize    = (float)(opt?.SizeOfCode ?? 0);
            var dataSize    = (float)(opt?.SizeOfInitializedData ?? 0);
            var imageSize   = (float)(opt?.SizeOfImage ?? 1);
            var ep          = (float)(opt?.AddressOfEntryPoint ?? 0);

            var numDirs = (float)(pe.ImageNtHeaders.OptionalHeader?.DataDirectory?
                .Count(d => d.VirtualAddress != 0) ?? 0);

            var characteristics = (float)(fh.Characteristics) / 65535f;
            var subsystem       = (float)(opt?.Subsystem ?? 0);
            var majorOs         = (float)(opt?.MajorOperatingSystemVersion ?? 0);
            var majorLinker     = (float)(opt?.MajorLinkerVersion ?? 0);
            var optHeaderSize   = (float)(fh.SizeOfOptionalHeader) / 512f;

            var timestamp = (float)fh.TimeDateStamp / (float)uint.MaxValue;

            // Overlay: file size > (last section raw offset + raw size)
            var hasOverlay = 0f;
            if (sections.Count > 0)
            {
                var last = sections[^1];
                var endOfLastSection = last.PointerToRawData + last.SizeOfRawData;
                if (fileSizeBytes > endOfLastSection + 512) hasOverlay = 1f;
            }

            var anomalies = 0f;
            if (maxEntropy >= 7.5f) anomalies++;
            if (numImports < 5f && pe.IsDotNet == false) anomalies++;
            if (suspCount > 0) anomalies++;
            if (hasOverlay > 0) anomalies++;

            return
            [
                fileSizeBytes / 1024f,                           // 0  file_size_kb
                numSections,                                     // 1  num_sections
                avgEntropy,                                      // 2  avg_section_entropy
                maxEntropy,                                      // 3  max_section_entropy
                minEntropy,                                      // 4  min_section_entropy
                stdEntropy,                                      // 5  std_section_entropy
                highEntropySections,                             // 6  num_high_entropy_sections
                pe.Is64Bit ? 1f : 0f,                           // 7  is_64bit
                pe.IsDll ? 1f : 0f,                             // 8  is_dll
                pe.IsDotNet ? 1f : 0f,                          // 9  is_dotnet
                pe.IsAuthenticodeSigned ? 1f : 0f,              // 10 is_signed
                (pe.ImageNtHeaders.OptionalHeader?.DataDirectory?.Length > 9
                    && pe.ImageNtHeaders.OptionalHeader.DataDirectory[9].VirtualAddress != 0) ? 1f : 0f, // 11 has_tls
                (pe.ImageNtHeaders.OptionalHeader?.DataDirectory?.Length > 6
                    && pe.ImageNtHeaders.OptionalHeader.DataDirectory[6].VirtualAddress != 0) ? 1f : 0f, // 12 has_debug
                (pe.ImageNtHeaders.OptionalHeader?.DataDirectory?.Length > 2
                    && pe.ImageNtHeaders.OptionalHeader.DataDirectory[2].VirtualAddress != 0) ? 1f : 0f, // 13 has_resources
                hasOverlay,                                      // 14 has_overlay
                numImports,                                      // 15 num_imports
                numExports,                                      // 16 num_exports
                suspCount,                                       // 17 num_suspicious_imports
                importHash,                                      // 18 import_hash_norm
                imageSize > 0 ? codeSize / imageSize : 0f,      // 19 ratio_code_to_file
                imageSize > 0 ? dataSize / imageSize : 0f,      // 20 ratio_data_to_file
                imageSize > 0 ? ep / imageSize : 0f,            // 21 entry_point_norm
                numDirs,                                         // 22 num_directories
                characteristics,                                 // 23 characteristics_norm
                subsystem,                                       // 24 subsystem
                majorOs,                                         // 25 major_os_version
                majorLinker,                                     // 26 major_linker_version
                optHeaderSize,                                   // 27 optional_header_size_norm
                anomalies,                                       // 28 num_anomalies
                timestamp,                                       // 29 timestamp_norm
            ];
        }
        catch
        {
            return null;
        }
    }

    private static float ComputeImportHashNorm(PeNet.Header.Pe.ImportFunction[] imports)
    {
        if (imports.Length == 0) return 0f;
        var parts = imports
            .Where(i => i.DLL is not null && i.Name is not null)
            .Select(i => $"{i.DLL!.ToLowerInvariant().Replace(".dll", "")}.{i.Name!.ToLowerInvariant()}")
            .OrderBy(s => s)
            .ToList();

        var combined = string.Join(",", parts);
        var hash = (uint)combined.GetHashCode();
        return hash / (float)uint.MaxValue;
    }

    private static float StdDev(List<float> values)
    {
        if (values.Count < 2) return 0f;
        var mean = values.Average();
        var variance = values.Select(v => (v - mean) * (v - mean)).Average();
        return (float)Math.Sqrt(variance);
    }

    private static bool HasMzHeader(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length < 2) return false;
            Span<byte> h = stackalloc byte[2];
            return fs.Read(h) == 2 && h[0] == (byte)'M' && h[1] == (byte)'Z';
        }
        catch { return false; }
    }
}

using System.Management;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class VssBackupService : IVssBackupService
{
    public async Task<string?> CreateSnapshotAsync(string volume, CancellationToken ct = default)
    {
        return await Task.Run<string?>(() =>
        {
            try
            {
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var mgmtPath = new ManagementPath("Win32_ShadowCopy");
                using var cls = new ManagementClass(scope, mgmtPath, null);
                using var inParams = cls.GetMethodParameters("Create");
                inParams["Volume"] = volume.EndsWith('\\') ? volume : volume + "\\";
                inParams["Context"] = "ClientAccessible";
                using var result = cls.InvokeMethod("Create", inParams, null);
                if (result == null) return null;
                var returnValue = result["ReturnValue"]?.ToString();
                if (returnValue != "0") return null;
                return result["ShadowID"]?.ToString();
            }
            catch
            {
                return null;
            }
        }, ct);
    }

    public async Task DeleteSnapshotAsync(string shadowId, CancellationToken ct = default)
    {
        await Task.Run(() =>
        {
            try
            {
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery($"SELECT * FROM Win32_ShadowCopy WHERE ID = '{shadowId}'");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    obj.Delete();
                    obj.Dispose();
                }
            }
            catch { }
        }, ct);
    }

    public async Task<IReadOnlyList<ShadowCopyInfo>> ListSnapshotsAsync(CancellationToken ct = default)
    {
        return await Task.Run<IReadOnlyList<ShadowCopyInfo>>(() =>
        {
            var result = new List<ShadowCopyInfo>();
            try
            {
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT * FROM Win32_ShadowCopy");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        var id = obj["ID"]?.ToString() ?? string.Empty;
                        var volumeName = obj["VolumeName"]?.ToString() ?? string.Empty;
                        var installDateRaw = obj["InstallDate"]?.ToString() ?? string.Empty;
                        DateTime createdAt = DateTime.MinValue;
                        if (!string.IsNullOrEmpty(installDateRaw))
                        {
                            try
                            {
                                createdAt = ManagementDateTimeConverter.ToDateTime(installDateRaw);
                            }
                            catch { }
                        }
                        result.Add(new ShadowCopyInfo(id, volumeName, createdAt));
                        obj.Dispose();
                    }
                    catch { obj.Dispose(); }
                }
            }
            catch { }
            return result;
        }, ct);
    }
}

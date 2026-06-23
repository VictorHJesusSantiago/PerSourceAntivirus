using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class SupplyChainDetector(ISupplyChainAlertRepository repo) : ISupplyChainDetector
{
    private static readonly HashSet<string> KnownCompromisedHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600",
        "6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9",
        "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
    };

    private CancellationTokenSource? _cts;
    private Task? _monitorTask;

    public event EventHandler<SupplyChainAlertEventArgs>? AlertDetected;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _monitorTask = RunMonitorLoopAsync(_cts.Token);
        await Task.CompletedTask;
    }

    public void StopMonitoring()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private async Task RunMonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var alerts = await ScanRunningProcessesAsync(ct);
                foreach (var alert in alerts)
                {
                    await repo.AddAsync(alert, ct);
                    AlertDetected?.Invoke(this, new SupplyChainAlertEventArgs(alert));
                }
            }
            catch (OperationCanceledException) { break; }
            catch { }

            try { await Task.Delay(TimeSpan.FromSeconds(60), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task<IReadOnlyList<SupplyChainAlert>> ScanRunningProcessesAsync(CancellationToken ct = default)
    {
        return await Task.Run<IReadOnlyList<SupplyChainAlert>>(() =>
        {
            var alerts = new List<SupplyChainAlert>();
            var now = DateTime.UtcNow;

            foreach (var process in SysProcess.GetProcesses())
            {
                try
                {
                    if (process.Id <= 4) { process.Dispose(); continue; }
                    string? filePath = null;
                    try { filePath = process.MainModule?.FileName; }
                    catch { }
                    if (string.IsNullOrEmpty(filePath)) { process.Dispose(); continue; }

                    ScanFile(filePath, process.ProcessName, process.Id, alerts, now);
                }
                catch { }
                finally
                {
                    try { process.Dispose(); } catch { }
                }
            }

            return alerts;
        }, ct);
    }

    private static void ScanFile(string filePath, string processName, int pid, List<SupplyChainAlert> alerts, DateTime now)
    {
        var fileHash = ComputeSha256(filePath);

        if (!string.IsNullOrEmpty(fileHash) && KnownCompromisedHashes.Contains(fileHash))
        {
            alerts.Add(new SupplyChainAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = processName,
                FilePath = filePath,
                Publisher = GetPublisher(filePath),
                CertificateThumbprint = GetCertThumbprint(filePath),
                AlertType = "KnownCompromisedBinary",
                Details = $"File matches known supply-chain compromised binary hash: {fileHash}",
                Severity = 10,
                DetectedAtUtc = now
            });
            return;
        }

        CheckRevokedCertificate(filePath, processName, alerts, now);
        CheckDllHijacking(filePath, processName, alerts, now);
    }

    private static void CheckRevokedCertificate(string filePath, string processName, List<SupplyChainAlert> alerts, DateTime now)
    {
        try
        {
            var rawCert = X509Certificate.CreateFromSignedFile(filePath);
            var cert2 = new X509Certificate2(rawCert);
            var thumbprint = cert2.Thumbprint;
            var publisher = cert2.Subject;

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);

            var valid = chain.Build(cert2);
            if (!valid)
            {
                foreach (var status in chain.ChainStatus)
                {
                    if (status.Status.HasFlag(X509ChainStatusFlags.Revoked)
                        || status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown))
                    {
                        alerts.Add(new SupplyChainAlert
                        {
                            Id = Guid.NewGuid(),
                            ProcessName = processName,
                            FilePath = filePath,
                            Publisher = publisher,
                            CertificateThumbprint = thumbprint,
                            AlertType = "RevokedCertificate",
                            Details = $"Certificate chain validation failed: {status.StatusInformation.Trim()}",
                            Severity = 9,
                            DetectedAtUtc = now
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }

    private static void CheckDllHijacking(string exePath, string processName, List<SupplyChainAlert> alerts, DateTime now)
    {
        try
        {
            var exeDir = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(exeDir)) return;

            var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
            var systemRoot32 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86).ToLowerInvariant();
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

            var exeDirLower = exeDir.ToLowerInvariant();
            if (exeDirLower.StartsWith(systemRoot) || exeDirLower.StartsWith(systemRoot32)
                || exeDirLower.StartsWith(winDir)) return;

            foreach (var dll in Directory.EnumerateFiles(exeDir, "*.dll", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var dllName = Path.GetFileName(dll).ToLowerInvariant();
                    var sysPath = Path.Combine(systemRoot, dllName);
                    if (!File.Exists(sysPath)) continue;

                    var isSigned = IsSigned(dll);
                    if (!isSigned)
                    {
                        alerts.Add(new SupplyChainAlert
                        {
                            Id = Guid.NewGuid(),
                            ProcessName = processName,
                            FilePath = dll,
                            Publisher = string.Empty,
                            CertificateThumbprint = string.Empty,
                            AlertType = "DllHijacking",
                            Details = $"Unsigned DLL '{dllName}' found in non-system directory alongside signed executable '{exePath}'; system version exists at '{sysPath}'",
                            Severity = 8,
                            DetectedAtUtc = now
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static bool IsSigned(string filePath)
    {
        try
        {
            X509Certificate.CreateFromSignedFile(filePath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ComputeSha256(string filePath)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            var hash = SHA256.HashData(fs);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string GetPublisher(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return new X509Certificate2(cert).Subject;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string GetCertThumbprint(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return new X509Certificate2(cert).Thumbprint;
        }
        catch
        {
            return string.Empty;
        }
    }
}

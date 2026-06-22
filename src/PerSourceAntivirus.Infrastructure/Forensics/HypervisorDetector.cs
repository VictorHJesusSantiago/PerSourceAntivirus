using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Forensics;

[SupportedOSPlatform("windows")]
public sealed class HypervisorDetector : IHypervisorDetector
{
    private static readonly string[] VmwareIndicators =
        ["vmtoolsd", "vmwaretray", "vmacthlp", "vmmouse", "vmsrvc"];
    private static readonly string[] HyperVIndicators =
        ["vmbus", "hvhost", "vmicheartbeat", "vmickvpexchange"];
    private static readonly string[] VboxIndicators =
        ["vboxservice", "vboxdrv", "vboxguest", "vboxtray"];
    private static readonly string[] KvmIndicators =
        ["kvm", "qemu-ga"];

    public async Task<HypervisorDetectionResult> DetectAsync(CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var methods = new List<string>();
            var hypervisorType = "None";
            var cpuidLeaf = string.Empty;
            var isVm = false;

            cpuidLeaf = DetectViaCpuProcessorName(ref isVm, ref hypervisorType, methods);
            DetectViaServices(ref isVm, ref hypervisorType, methods);
            DetectViaRegistry(ref isVm, ref hypervisorType, methods);

            return new HypervisorDetectionResult
            {
                Id = Guid.NewGuid(),
                IsVirtualMachine = isVm,
                HypervisorType = hypervisorType,
                DetectionMethods = string.Join("; ", methods),
                CpuidLeaf = cpuidLeaf,
                DetectedAtUtc = DateTime.UtcNow
            };
        }, ct);
    }

    private static string DetectViaCpuProcessorName(ref bool isVm, ref string hypervisorType, List<string> methods)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            if (key == null) return string.Empty;

            var processorName = key.GetValue("ProcessorNameString")?.ToString() ?? string.Empty;
            var lower = processorName.ToLowerInvariant();

            if (lower.Contains("vmware") || lower.Contains("virtual cpu"))
            {
                isVm = true;
                if (hypervisorType == "None") hypervisorType = "VMware";
                methods.Add($"CPU processor name contains VM signature: {processorName}");
            }
            else if (lower.Contains("kvm") || lower.Contains("qemu"))
            {
                isVm = true;
                if (hypervisorType == "None") hypervisorType = "KVM/QEMU";
                methods.Add($"CPU processor name contains KVM/QEMU signature: {processorName}");
            }
            else if (lower.Contains("microsoft") && lower.Contains("virtual"))
            {
                isVm = true;
                if (hypervisorType == "None") hypervisorType = "Hyper-V";
                methods.Add($"CPU processor name contains Hyper-V signature: {processorName}");
            }

            return processorName;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static void DetectViaServices(ref bool isVm, ref string hypervisorType, List<string> methods)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            var serviceNames = servicesKey.GetSubKeyNames()
                .Select(n => n.ToLowerInvariant())
                .ToHashSet();

            foreach (var indicator in VmwareIndicators)
            {
                if (serviceNames.Contains(indicator))
                {
                    isVm = true;
                    if (hypervisorType == "None") hypervisorType = "VMware";
                    methods.Add($"VMware service/driver found: {indicator}");
                }
            }

            foreach (var indicator in HyperVIndicators)
            {
                if (serviceNames.Contains(indicator))
                {
                    isVm = true;
                    if (hypervisorType == "None") hypervisorType = "Hyper-V";
                    methods.Add($"Hyper-V service/driver found: {indicator}");
                }
            }

            foreach (var indicator in VboxIndicators)
            {
                if (serviceNames.Contains(indicator))
                {
                    isVm = true;
                    if (hypervisorType == "None") hypervisorType = "VirtualBox";
                    methods.Add($"VirtualBox service/driver found: {indicator}");
                }
            }

            foreach (var indicator in KvmIndicators)
            {
                if (serviceNames.Contains(indicator))
                {
                    isVm = true;
                    if (hypervisorType == "None") hypervisorType = "KVM";
                    methods.Add($"KVM service/driver found: {indicator}");
                }
            }
        }
        catch { }
    }

    private static void DetectViaRegistry(ref bool isVm, ref string hypervisorType, List<string> methods)
    {
        try
        {
            using var vmwareKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\VMware, Inc.");
            if (vmwareKey != null)
            {
                isVm = true;
                if (hypervisorType == "None") hypervisorType = "VMware";
                methods.Add("VMware registry key found: SOFTWARE\\VMware, Inc.");
            }
        }
        catch { }

        try
        {
            using var vboxKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Oracle\VirtualBox Guest Additions");
            if (vboxKey != null)
            {
                isVm = true;
                if (hypervisorType == "None") hypervisorType = "VirtualBox";
                methods.Add("VirtualBox registry key found: SOFTWARE\\Oracle\\VirtualBox Guest Additions");
            }
        }
        catch { }

        try
        {
            using var hyperVKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters");
            if (hyperVKey != null)
            {
                isVm = true;
                if (hypervisorType == "None") hypervisorType = "Hyper-V";
                methods.Add("Hyper-V registry key found: SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
            }
        }
        catch { }
    }
}

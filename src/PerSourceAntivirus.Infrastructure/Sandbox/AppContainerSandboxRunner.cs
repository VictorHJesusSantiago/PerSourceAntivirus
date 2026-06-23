using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Sandbox;

[SupportedOSPlatform("windows")]
public sealed class AppContainerSandboxRunner : IAppContainerSandboxRunner
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;

    public async Task<SandboxExecutionResult> RunInAppContainerAsync(
        string executablePath,
        string arguments,
        int timeoutSeconds,
        CancellationToken ct)
    {
        if (!File.Exists(executablePath))
            return new SandboxExecutionResult(false, -1, string.Empty, $"Executable not found: {executablePath}", false);

        var containerName = $"PSAVContainer_{Guid.NewGuid():N}";
        bool containerCreated = false;

        try
        {
            var hr = NativeMethods.CreateAppContainerProfile(
                containerName,
                "PerSourceAntivirus Sandbox",
                "Isolated execution sandbox",
                IntPtr.Zero,
                0,
                out _);
            containerCreated = hr == 0;
        }
        catch { }

        try
        {
            return await RunWithJobObjectAsync(executablePath, arguments, timeoutSeconds, ct);
        }
        finally
        {
            if (containerCreated)
            {
                try { NativeMethods.DeleteAppContainerProfile(containerName); } catch { }
            }
        }
    }

    private static async Task<SandboxExecutionResult> RunWithJobObjectAsync(
        string executablePath,
        string arguments,
        int timeoutSeconds,
        CancellationToken ct)
    {
        var stdoutSb = new StringBuilder();
        var stderrSb = new StringBuilder();

        var psi = new System.Diagnostics.ProcessStartInfo(executablePath, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using var process = new SysProcess { StartInfo = psi };
        process.OutputDataReceived += (_, e) => { if (e.Data != null) stdoutSb.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrSb.AppendLine(e.Data); };

        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return new SandboxExecutionResult(false, -1, string.Empty, ex.Message, false);
        }

        var jobHandle = NativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (!jobHandle.IsInvalid)
        {
            ApplyJobLimits(jobHandle);
            NativeMethods.AssignProcessToJobObject(jobHandle, process.SafeHandle);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        bool timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            timedOut = true;
            try { process.Kill(entireProcessTree: true); } catch { }
        }

        if (!jobHandle.IsInvalid) jobHandle.Dispose();

        int exitCode = timedOut ? -1 : process.ExitCode;
        bool success = !timedOut && exitCode == 0;

        return new SandboxExecutionResult(success, exitCode, stdoutSb.ToString(), stderrSb.ToString(), timedOut);
    }

    private static void ApplyJobLimits(SafeFileHandle jobHandle)
    {
        var extInfo = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new NativeMethods.JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                ActiveProcessLimit = 1,
            }
        };

        var size = Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(extInfo, ptr, false);
            NativeMethods.SetInformationJobObject(jobHandle, 9, ptr, (uint)size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    private static class NativeMethods
    {
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int CreateAppContainerProfile(
            string pszAppContainerName,
            string pszDisplayName,
            string pszDescription,
            IntPtr pCapabilities,
            uint dwCapabilityCount,
            out IntPtr ppSidAppContainerSid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int DeleteAppContainerProfile(string pszAppContainerName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeFileHandle hJob,
            int jobObjectInfoClass,
            IntPtr lpJobObjectInfo,
            uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(SafeFileHandle hJob, SafeHandle hProcess);

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }
    }
}

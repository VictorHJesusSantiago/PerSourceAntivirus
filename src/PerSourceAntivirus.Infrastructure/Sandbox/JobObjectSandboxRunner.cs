using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Sandbox;

// Runs an executable inside a Windows Job Object that restricts resource usage.
// Restrictions: kill-on-job-close, active process limit = 1 (blocks child spawning).
public sealed class JobObjectSandboxRunner : ISandboxRunner
{
    public async Task<SandboxRunResult> RunAsync(
        string exePath,
        int timeoutSeconds = 30,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return new SandboxRunResult(null, TimeSpan.Zero, false, false, false,
                "Job Object sandbox is only supported on Windows.");

        if (!File.Exists(exePath))
            return new SandboxRunResult(null, TimeSpan.Zero, false, false, false,
                $"Executable not found: {exePath}");

        var jobHandle = NativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (jobHandle.IsInvalid)
            return new SandboxRunResult(null, TimeSpan.Zero, false, false, false,
                $"CreateJobObject failed: {Marshal.GetLastWin32Error()}");

        try
        {
            ApplyJobLimits(jobHandle);

            var psi = new System.Diagnostics.ProcessStartInfo(exePath)
            {
                UseShellExecute = false,
                CreateNoWindow  = true,
            };

            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var process = System.Diagnostics.Process.Start(psi)
                ?? throw new InvalidOperationException("Process.Start returned null.");

            if (!NativeMethods.AssignProcessToJobObject(jobHandle, process.SafeHandle))
            {
                process.Kill();
                return new SandboxRunResult(null, sw.Elapsed, false, false, false,
                    $"AssignProcessToJobObject failed: {Marshal.GetLastWin32Error()}");
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            bool killedByTimeout = false;
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                killedByTimeout = true;
                try { process.Kill(entireProcessTree: true); } catch { /* already exited */ }
            }

            sw.Stop();
            int? exitCode = killedByTimeout ? null : process.ExitCode;
            bool childCreated = CheckChildProcessCreated(process);

            return new SandboxRunResult(exitCode, sw.Elapsed, killedByTimeout, childCreated, false, null);
        }
        catch (Exception ex)
        {
            return new SandboxRunResult(null, TimeSpan.Zero, false, false, false, ex.Message);
        }
        finally
        {
            jobHandle.Dispose();
        }
    }

    private static void ApplyJobLimits(SafeFileHandle jobHandle)
    {
        var extInfo = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new NativeMethods.JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags         = NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                     NativeMethods.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                ActiveProcessLimit = 1,
            }
        };

        var size = Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        var ptr  = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(extInfo, ptr, false);
            NativeMethods.SetInformationJobObject(
                jobHandle,
                NativeMethods.JobObjectInfoClass.ExtendedLimitInformation,
                ptr, (uint)size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    // Rough heuristic: the process had child processes if any process started after it.
    // Job Object with ActiveProcessLimit=1 would have prevented actual spawning, so
    // this flag reflects whether the sandbox would have blocked a child process attempt.
    private static bool CheckChildProcessCreated(System.Diagnostics.Process process)
    {
        try
        {
            return System.Diagnostics.Process.GetProcesses()
                .Any(p =>
                {
                    try { return p.Id != process.Id && p.StartTime > process.StartTime; }
                    catch { return false; }
                });
        }
        catch { return false; }
    }

    private static class NativeMethods
    {
        internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        internal const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS     = 0x00000008;

        internal enum JobObjectInfoClass
        {
            ExtendedLimitInformation = 9,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long    PerProcessUserTimeLimit;
            public long    PerJobUserTimeLimit;
            public uint    LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint    ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint    PriorityClass;
            public uint    SchedulingClass;
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
            public IO_COUNTERS                       IoInfo;
            public UIntPtr                           ProcessMemoryLimit;
            public UIntPtr                           JobMemoryLimit;
            public UIntPtr                           PeakProcessMemoryUsed;
            public UIntPtr                           PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeFileHandle hJob,
            JobObjectInfoClass jobObjectInfoClass,
            IntPtr lpJobObjectInfo,
            uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(SafeFileHandle hJob, SafeHandle hProcess);
    }
}

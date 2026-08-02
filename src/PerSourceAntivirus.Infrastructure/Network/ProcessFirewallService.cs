using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class ProcessFirewallService : IProcessFirewallService, IDisposable
{
    // FWPM_LAYER_ALE_AUTH_CONNECT_V4 / V6
    private static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid LayerConnectV6 = new("4a72393b-7b55-493c-b3eb-d9e11cd3f8df");
    // FWPM_CONDITION_ALE_APP_ID
    private static readonly Guid CondAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    // A dedicated sublayer for per-process rules (distinct from WfpBlocker's IP sublayer)
    private static readonly Guid AppFirewallSubLayer = new("7f4a9b1c-2d3e-4f5a-8b6c-9d0e1f2a3b4c");

    private const uint FwpByteBlobType = 4; // FWP_BYTE_BLOB_TYPE
    private const uint FwpMatchEqual = 0;
    private const uint FwpEmpty = 0;
    private const uint FwpActionBlock = 0x00000001;
    private const uint RpcCAuthnDefault = 0xFFFFFFFF;

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly Dictionary<string, (ulong outIdV4, ulong outIdV6)> _active = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();
    private nint _engine = nint.Zero;
    private bool _subLayerAdded;

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0 { public nint Name; public nint Description; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpValue0 { public uint Type; private uint _pad; public ulong Value; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob { public uint Size; private uint _pad; public nint Data; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterCondition0
    {
        public Guid FieldKey;
        public uint MatchType;
        private uint _pad;
        public FwpValue0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0 { public uint Type; public Guid FilterType; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilter0
    {
        public Guid FilterKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        private uint _pad1;
        public nint ProviderKey;
        public FwpByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public FwpValue0 Weight;
        public uint NumFilterConditions;
        private uint _pad2;
        public nint FilterCondition;
        public FwpmAction0 Action;
        private uint _pad3;
        public ulong RawContext;
        private ulong _contextPad;
        public nint Reserved;
        public ulong FilterId;
        public FwpValue0 EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmSublayer0
    {
        public Guid SubLayerKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        private uint _pad;
        public nint ProviderKey;
        public FwpByteBlob ProviderData;
        public ushort Weight;
        private ushort _wpad1;
        private uint _wpad2;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, nint authIdentity, nint session, out nint engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(nint engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionBegin0(nint engineHandle, uint flags);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionCommit0(nint engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionAbort0(nint engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern unsafe uint FwpmSubLayerAdd0(nint engineHandle, FwpmSublayer0* subLayer, nint sd);

    [DllImport("fwpuclnt.dll")]
    private static extern unsafe uint FwpmFilterAdd0(nint engineHandle, FwpmFilter0* filter, nint sd, out ulong filterId);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteById0(nint engineHandle, ulong filterId);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern unsafe uint FwpmGetAppIdFromFileName0(string fileName, FwpByteBlob** appId);

    [DllImport("fwpuclnt.dll")]
    private static extern unsafe uint FwpmFreeMemory0(void** p);

    public ProcessFirewallService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task<bool> BlockProcessAsync(string exePath, string? reason = null, CancellationToken ct = default)
    {
        exePath = Path.GetFullPath(exePath);

        bool added;
        lock (_lock)
        {
            if (_active.ContainsKey(exePath)) return true;

            try
            {
                added = TryAddAppIdFilters(exePath, reason ?? "Blocked by application firewall", out var ids);
                if (added) _active[exePath] = ids;
            }
            catch
            {
                added = false;
            }
        }

        if (added)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var repository = scope.ServiceProvider.GetRequiredService<IProcessFirewallRuleRepository>();
                await repository.AddAsync(new ProcessFirewallRule
                {
                    Id = Guid.NewGuid(),
                    ProcessPath = exePath,
                    Action = "Block",
                    Reason = reason,
                    AddedAtUtc = DateTime.UtcNow
                }, ct).ConfigureAwait(false);
            }
            catch { }
        }

        return added;
    }

    public async Task<bool> UnblockProcessAsync(string exePath, CancellationToken ct = default)
    {
        exePath = Path.GetFullPath(exePath);

        bool removed;
        lock (_lock)
        {
            if (!_active.TryGetValue(exePath, out var ids)) { removed = false; }
            else
            {
                try
                {
                    if (ids.outIdV4 != 0) FwpmFilterDeleteById0(_engine, ids.outIdV4);
                    if (ids.outIdV6 != 0) FwpmFilterDeleteById0(_engine, ids.outIdV6);
                    _active.Remove(exePath);
                    removed = true;
                }
                catch { removed = false; }
            }
        }

        if (removed)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var repository = scope.ServiceProvider.GetRequiredService<IProcessFirewallRuleRepository>();
                await repository.RemoveAsync(exePath, ct).ConfigureAwait(false);
            }
            catch { }
        }

        return removed;
    }

    public Task<IReadOnlyList<string>> GetBlockedProcessesAsync(CancellationToken ct = default)
    {
        lock (_lock)
        {
            IReadOnlyList<string> result = _active.Keys.ToList();
            return Task.FromResult(result);
        }
    }

    public async Task RestoreRulesFromRepositoryAsync(CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IProcessFirewallRuleRepository>();
        var rules = await repository.GetAllAsync(ct).ConfigureAwait(false);

        foreach (var rule in rules.Where(r => r.Action == "Block"))
        {
            ct.ThrowIfCancellationRequested();
            lock (_lock)
            {
                if (_active.ContainsKey(rule.ProcessPath)) continue;
                try
                {
                    if (TryAddAppIdFilters(rule.ProcessPath, rule.Reason ?? "Restored rule", out var ids))
                        _active[rule.ProcessPath] = ids;
                }
                catch { }
            }
        }
    }

    private unsafe bool TryAddAppIdFilters(string exePath, string reason, out (ulong outIdV4, ulong outIdV6) ids)
    {
        ids = (0, 0);
        if (!File.Exists(exePath)) return false;

        EnsureEngine();

        FwpByteBlob* appId = null;
        var hr = FwpmGetAppIdFromFileName0(exePath, &appId);
        if (hr != 0 || appId == null) return false;

        var namePtr = Marshal.StringToHGlobalUni($"PSAV process block {Path.GetFileName(exePath)}");
        var descPtr = Marshal.StringToHGlobalUni(reason);
        try
        {
            var condition = new FwpmFilterCondition0
            {
                FieldKey = CondAppId,
                MatchType = FwpMatchEqual,
                ConditionValue = new FwpValue0 { Type = FwpByteBlobType, Value = (ulong)appId }
            };

            ulong outIdV4, outIdV6;

            FwpmTransactionBegin0(_engine, 0);
            var filterV4 = new FwpmFilter0
            {
                FilterKey = Guid.NewGuid(),
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey = LayerConnectV4,
                SubLayerKey = AppFirewallSubLayer,
                NumFilterConditions = 1,
                FilterCondition = (nint)(&condition),
                Action = new FwpmAction0 { Type = FwpActionBlock },
                Weight = new FwpValue0 { Type = FwpEmpty }
            };
            var addHr = FwpmFilterAdd0(_engine, &filterV4, nint.Zero, out outIdV4);
            if (addHr != 0) { FwpmTransactionAbort0(_engine); return false; }
            FwpmTransactionCommit0(_engine);

            FwpmTransactionBegin0(_engine, 0);
            var filterV6 = new FwpmFilter0
            {
                FilterKey = Guid.NewGuid(),
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey = LayerConnectV6,
                SubLayerKey = AppFirewallSubLayer,
                NumFilterConditions = 1,
                FilterCondition = (nint)(&condition),
                Action = new FwpmAction0 { Type = FwpActionBlock },
                Weight = new FwpValue0 { Type = FwpEmpty }
            };
            addHr = FwpmFilterAdd0(_engine, &filterV6, nint.Zero, out outIdV6);
            if (addHr != 0) { FwpmTransactionAbort0(_engine); FwpmFilterDeleteById0(_engine, outIdV4); return false; }
            FwpmTransactionCommit0(_engine);

            ids = (outIdV4, outIdV6);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
            void* p = appId;
            FwpmFreeMemory0(&p);
        }
    }

    private void EnsureEngine()
    {
        if (_engine != nint.Zero) return;

        var hr = FwpmEngineOpen0(null, RpcCAuthnDefault, nint.Zero, nint.Zero, out _engine);
        if (hr != 0) throw new InvalidOperationException($"FwpmEngineOpen0 failed: 0x{hr:X8}. Run as admin.");

        EnsureSubLayer();
    }

    private unsafe void EnsureSubLayer()
    {
        if (_subLayerAdded) return;

        var namePtr = Marshal.StringToHGlobalUni("PSAV Application Firewall Sublayer");
        var descPtr = Marshal.StringToHGlobalUni("PerSourceAntivirus per-process outbound block sublayer");
        try
        {
            FwpmTransactionBegin0(_engine, 0);
            var sl = new FwpmSublayer0
            {
                SubLayerKey = AppFirewallSubLayer,
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                Weight = 0x8000
            };
            var hr = FwpmSubLayerAdd0(_engine, &sl, nint.Zero);
            if (hr != 0 && hr != 0x80320009) // FWP_E_ALREADY_EXISTS
            {
                FwpmTransactionAbort0(_engine);
                throw new InvalidOperationException($"FwpmSubLayerAdd0 failed: 0x{hr:X8}");
            }
            FwpmTransactionCommit0(_engine);
            _subLayerAdded = true;
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_engine != nint.Zero) { FwpmEngineClose0(_engine); _engine = nint.Zero; }
        }
    }
}

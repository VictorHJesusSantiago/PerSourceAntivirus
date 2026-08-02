using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class HostIsolationService : IHostIsolationService, IDisposable
{
    private static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid LayerConnectV6 = new("4a72393b-7b55-493c-b3eb-d9e11cd3f8df");
    private static readonly Guid LayerRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    private static readonly Guid LayerRecvAcceptV6 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8651");
    private static readonly Guid IsolationSubLayer = new("9c8b7a6d-5e4f-4a3b-8c1d-2e3f4a5b6c7d");

    private const uint FwpEmpty = 0;
    private const uint FwpActionBlock = 0x00000001;
    private const uint RpcCAuthnDefault = 0xFFFFFFFF;

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly Lock _lock = new();
    private nint _engine = nint.Zero;
    private readonly List<ulong> _activeFilterIds = new();

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0 { public nint Name; public nint Description; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpValue0 { public uint Type; private uint _pad; public ulong Value; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob { public uint Size; private uint _pad; public nint Data; }

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

    public bool IsIsolated { get; private set; }

    public HostIsolationService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task IsolateAsync(string reason, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (IsIsolated) return;
            EnsureEngine();

            foreach (var layer in new[] { LayerConnectV4, LayerConnectV6, LayerRecvAcceptV4, LayerRecvAcceptV6 })
                _activeFilterIds.Add(AddBlockAllFilter(layer));

            IsIsolated = true;
        }

        await PersistAsync("Isolated", reason, ct).ConfigureAwait(false);
    }

    public async Task RestoreAsync(CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (!IsIsolated) return;

            foreach (var id in _activeFilterIds)
            {
                try { FwpmFilterDeleteById0(_engine, id); } catch { }
            }
            _activeFilterIds.Clear();
            IsIsolated = false;
        }

        await PersistAsync("Restored", "Manual restore", ct).ConfigureAwait(false);
    }

    private async Task PersistAsync(string action, string reason, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IHostIsolationEventRepository>();
            await repository.AddAsync(new HostIsolationEvent
            {
                Id = Guid.NewGuid(),
                Action = action,
                Reason = reason,
                TriggeredAtUtc = DateTime.UtcNow
            }, ct).ConfigureAwait(false);
        }
        catch { }
    }

    private unsafe ulong AddBlockAllFilter(Guid layerKey)
    {
        var namePtr = Marshal.StringToHGlobalUni("PSAV Host Isolation");
        var descPtr = Marshal.StringToHGlobalUni("Blocks all traffic — host isolated by PerSourceAntivirus");
        try
        {
            FwpmTransactionBegin0(_engine, 0);
            var filter = new FwpmFilter0
            {
                FilterKey = Guid.NewGuid(),
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey = layerKey,
                SubLayerKey = IsolationSubLayer,
                NumFilterConditions = 0, // no conditions = matches everything on this layer
                FilterCondition = nint.Zero,
                Action = new FwpmAction0 { Type = FwpActionBlock },
                Weight = new FwpValue0 { Type = FwpEmpty }
            };
            var hr = FwpmFilterAdd0(_engine, &filter, nint.Zero, out var filterId);
            if (hr != 0)
            {
                FwpmTransactionAbort0(_engine);
                throw new InvalidOperationException($"FwpmFilterAdd0 failed: 0x{hr:X8}");
            }
            FwpmTransactionCommit0(_engine);
            return filterId;
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
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
        var namePtr = Marshal.StringToHGlobalUni("PSAV Isolation Sublayer");
        var descPtr = Marshal.StringToHGlobalUni("PerSourceAntivirus host isolation sublayer — highest priority");
        try
        {
            FwpmTransactionBegin0(_engine, 0);
            var sl = new FwpmSublayer0
            {
                SubLayerKey = IsolationSubLayer,
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                Weight = 0xFFFF // highest weight — takes priority over all other PSAV sublayers
            };
            var hr = FwpmSubLayerAdd0(_engine, &sl, nint.Zero);
            if (hr != 0 && hr != 0x80320009) // FWP_E_ALREADY_EXISTS
            {
                FwpmTransactionAbort0(_engine);
                throw new InvalidOperationException($"FwpmSubLayerAdd0 failed: 0x{hr:X8}");
            }
            FwpmTransactionCommit0(_engine);
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

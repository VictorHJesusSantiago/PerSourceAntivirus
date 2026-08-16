using System.Net;
using System.Runtime.InteropServices;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class WfpBlocker : IWfpBlocker, IDisposable
{
    private static readonly Guid LayerConnectV4    = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid LayerRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    private static readonly Guid LayerConnectV6    = new("4a72393b-7b55-493c-b3eb-d9e11cd3f8df");
    private static readonly Guid LayerRecvAcceptV6 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8651");
    private static readonly Guid CondRemoteAddr    = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid CondLocalAddr     = new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    private static readonly Guid PsavSubLayer      = new("3a6b1a2c-9d4e-4f5a-8e7b-1c2d3e4f5a6b");

    private const uint FwpByteArray16 = 14;

    private const uint FwpEmpty     = 0;
    private const uint FwpUint32    = 3;
    private const uint FwpMatchEqual = 0;
    private const uint FwpActionBlock = 0x00000001;
    private const uint RpcCAuthnDefault = 0xFFFFFFFF;
    private const uint FwpmSessionFlagDynamic = 0x00000001;

    private readonly Dictionary<string, (ulong outId, ulong inId)> _active = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();
    private nint _engine = nint.Zero;
    private bool _disposed;
    private bool _subLayerAdded;


    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmDisplayData0
    {
        public nint Name;
        public nint Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpValue0
    {
        public uint Type;
        private uint _pad;
        public ulong Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint Size;
        private uint _pad;
        public nint Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterCondition0
    {
        public Guid FieldKey;
        public uint MatchType;
        private uint _pad;
        public FwpValue0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0
    {
        public uint Type;
        public Guid FilterType;
    }

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
        private uint   _wpad2;
    }


    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(
        string? serverName, uint authnService, nint authIdentity,
        nint session, out nint engineHandle);

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


    public Task<WfpBlockResult> AddBlockAsync(string ipAddress, string reason = "", CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (_active.ContainsKey(ipAddress))
                return Task.FromResult(new WfpBlockResult(true,
                    _active[ipAddress].outId, _active[ipAddress].inId));

            try
            {
                EnsureEngine();
                var parsed = System.Net.IPAddress.Parse(ipAddress);
                var (outId, inId) = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    ? AddIpV6Filters(ipAddress, reason)
                    : AddIpV4Filters(ipAddress, reason);
                _active[ipAddress] = (outId, inId);
                return Task.FromResult(new WfpBlockResult(true, outId, inId));
            }
            catch (Exception ex)
            {
                return Task.FromResult(new WfpBlockResult(false, 0, 0, ex.Message));
            }
        }
    }

    public Task<bool> RemoveBlockAsync(string ipAddress, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (!_active.TryGetValue(ipAddress, out var ids))
                return Task.FromResult(false);

            try
            {
                EnsureEngine();
                if (ids.outId != 0) FwpmFilterDeleteById0(_engine, ids.outId);
                if (ids.inId  != 0) FwpmFilterDeleteById0(_engine, ids.inId);
                _active.Remove(ipAddress);
                return Task.FromResult(true);
            }
            catch
            {
                return Task.FromResult(false);
            }
        }
    }

    public Task<IReadOnlyList<WfpBlockEntry>> GetActiveBlocksAsync(CancellationToken ct = default)
    {
        lock (_lock)
        {
            IReadOnlyList<WfpBlockEntry> result = _active
                .Select(kv => new WfpBlockEntry(kv.Key, kv.Value.outId, kv.Value.inId, string.Empty, DateTime.UtcNow))
                .ToList();
            return Task.FromResult(result);
        }
    }

    public async Task<int> SyncFromIpListAsync(IEnumerable<string> ipAddresses, CancellationToken ct = default)
    {
        var added = 0;
        foreach (var ip in ipAddresses)
        {
            ct.ThrowIfCancellationRequested();
            var r = await AddBlockAsync(ip, "blocklist-sync", ct);
            if (r.Success) added++;
        }
        return added;
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

        var namePtr = Marshal.StringToHGlobalUni("PSAV WFP Sublayer");
        var descPtr = Marshal.StringToHGlobalUni("PerSourceAntivirus IP block sublayer");
        try
        {
            FwpmTransactionBegin0(_engine, 0);
            var sl = new FwpmSublayer0
            {
                SubLayerKey = PsavSubLayer,
                DisplayData = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                Weight = 0x8000
            };
            var hr = FwpmSubLayerAdd0(_engine, &sl, nint.Zero);
            if (hr != 0 && hr != 0x80320009)
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

    private unsafe (ulong outId, ulong inId) AddIpV6Filters(string ipAddress, string reason)
    {
        if (!System.Net.IPAddress.TryParse(ipAddress, out var parsed) ||
            parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            throw new ArgumentException($"Invalid IPv6 address: {ipAddress}");

        var ipBytes = parsed.GetAddressBytes();

        var namePtr = Marshal.StringToHGlobalUni($"PSAV block {ipAddress}");
        var descPtr = Marshal.StringToHGlobalUni(string.IsNullOrEmpty(reason) ? "PerSourceAntivirus block" : reason);
        var addrPtr = Marshal.AllocHGlobal(16);
        try
        {
            Marshal.Copy(ipBytes, 0, addrPtr, 16);

            var condition = new FwpmFilterCondition0
            {
                FieldKey   = CondRemoteAddr,
                MatchType  = FwpMatchEqual,
                ConditionValue = new FwpValue0 { Type = FwpByteArray16, Value = (ulong)addrPtr }
            };

            ulong outId, inId;

            FwpmTransactionBegin0(_engine, 0);
            var filterOut = new FwpmFilter0
            {
                FilterKey        = Guid.NewGuid(),
                DisplayData      = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey         = LayerConnectV6,
                SubLayerKey      = PsavSubLayer,
                NumFilterConditions = 1,
                FilterCondition  = (nint)(&condition),
                Action           = new FwpmAction0 { Type = FwpActionBlock },
                Weight           = new FwpValue0 { Type = FwpEmpty }
            };
            var hr = FwpmFilterAdd0(_engine, &filterOut, nint.Zero, out outId);
            if (hr != 0) { FwpmTransactionAbort0(_engine); throw new InvalidOperationException($"FwpmFilterAdd0 (IPv6 out) failed: 0x{hr:X8}"); }
            FwpmTransactionCommit0(_engine);

            FwpmTransactionBegin0(_engine, 0);
            var filterIn = new FwpmFilter0
            {
                FilterKey        = Guid.NewGuid(),
                DisplayData      = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey         = LayerRecvAcceptV6,
                SubLayerKey      = PsavSubLayer,
                NumFilterConditions = 1,
                FilterCondition  = (nint)(&condition),
                Action           = new FwpmAction0 { Type = FwpActionBlock },
                Weight           = new FwpValue0 { Type = FwpEmpty }
            };
            hr = FwpmFilterAdd0(_engine, &filterIn, nint.Zero, out inId);
            if (hr != 0) { FwpmTransactionAbort0(_engine); throw new InvalidOperationException($"FwpmFilterAdd0 (IPv6 in) failed: 0x{hr:X8}"); }
            FwpmTransactionCommit0(_engine);

            return (outId, inId);
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
            Marshal.FreeHGlobal(addrPtr);
        }
    }

    private unsafe (ulong outId, ulong inId) AddIpV4Filters(string ipAddress, string reason)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException($"Invalid IPv4 address: {ipAddress}");

        var bytes = parsed.GetAddressBytes();
        var ipHostOrder = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);

        var namePtr = Marshal.StringToHGlobalUni($"PSAV block {ipAddress}");
        var descPtr = Marshal.StringToHGlobalUni(string.IsNullOrEmpty(reason) ? "PerSourceAntivirus block" : reason);
        try
        {
            var condition = new FwpmFilterCondition0
            {
                FieldKey   = CondRemoteAddr,
                MatchType  = FwpMatchEqual,
                ConditionValue = new FwpValue0 { Type = FwpUint32, Value = ipHostOrder }
            };

            ulong outId, inId;

            FwpmTransactionBegin0(_engine, 0);
            var filterOut = new FwpmFilter0
            {
                FilterKey        = Guid.NewGuid(),
                DisplayData      = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey         = LayerConnectV4,
                SubLayerKey      = PsavSubLayer,
                NumFilterConditions = 1,
                FilterCondition  = (nint)(&condition),
                Action           = new FwpmAction0 { Type = FwpActionBlock },
                Weight           = new FwpValue0 { Type = FwpEmpty }
            };
            var hr = FwpmFilterAdd0(_engine, &filterOut, nint.Zero, out outId);
            if (hr != 0) { FwpmTransactionAbort0(_engine); throw new InvalidOperationException($"FwpmFilterAdd0 (outbound) failed: 0x{hr:X8}"); }
            FwpmTransactionCommit0(_engine);

            FwpmTransactionBegin0(_engine, 0);
            var filterIn = new FwpmFilter0
            {
                FilterKey        = Guid.NewGuid(),
                DisplayData      = new FwpmDisplayData0 { Name = namePtr, Description = descPtr },
                LayerKey         = LayerRecvAcceptV4,
                SubLayerKey      = PsavSubLayer,
                NumFilterConditions = 1,
                FilterCondition  = (nint)(&condition),
                Action           = new FwpmAction0 { Type = FwpActionBlock },
                Weight           = new FwpValue0 { Type = FwpEmpty }
            };
            hr = FwpmFilterAdd0(_engine, &filterIn, nint.Zero, out inId);
            if (hr != 0) { FwpmTransactionAbort0(_engine); throw new InvalidOperationException($"FwpmFilterAdd0 (inbound) failed: 0x{hr:X8}"); }
            FwpmTransactionCommit0(_engine);

            return (outId, inId);
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        lock (_lock)
        {
            if (_engine != nint.Zero) { FwpmEngineClose0(_engine); _engine = nint.Zero; }
        }
        _disposed = true;
    }
}

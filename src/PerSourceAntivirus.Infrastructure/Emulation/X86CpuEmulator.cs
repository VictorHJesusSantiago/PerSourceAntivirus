// TODO: Register in DependencyInjection.cs as: services.AddSingleton<ICpuEmulator, X86CpuEmulator>();

using Iced.Intel;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Emulation;

public class X86CpuEmulator : ICpuEmulator
{
    // Well-known API hook addresses
    private static readonly Dictionary<ulong, string> ApiHookTable = new()
    {
        [0xDEAD_0001] = "VirtualAlloc",
        [0xDEAD_0002] = "WriteProcessMemory",
        [0xDEAD_0003] = "CreateRemoteThread",
        [0xDEAD_0004] = "CreateProcess",
        [0xDEAD_0005] = "ShellExecute",
        [0xDEAD_0006] = "WinExec",
    };

    public Task<EmulationSummary> EmulateAsync(
        string filePath,
        byte[] code,
        int maxInstructions = 10_000,
        CancellationToken ct = default)
    {
        var result = Emulate(code, maxInstructions);
        return Task.FromResult(result);
    }

    private static EmulationSummary Emulate(byte[] code, int maxInstructions)
    {
        if (code.Length == 0)
        {
            return new EmulationSummary(0, 0, false, []);
        }

        bool is64Bit = DetectIs64Bit(code);

        var registers = new Dictionary<Register, ulong>
        {
            [Register.RSP] = 0x0001_0000,
            [Register.RBP] = 0x0001_0000,
            [Register.RIP] = 0,
        };

        var memory = new Dictionary<ulong, byte>();
        var interceptedApis = new List<string>();
        var detectedPatterns = new List<string>();

        int instructionCount = 0;
        int xorLoopCount = 0;
        // Track addresses that have been written to
        var writtenAddresses = new HashSet<ulong>();
        // Track addresses that have been executed (for self-modifying code detection)
        var executedAddresses = new HashSet<ulong>();

        var codeReader = new ByteArrayCodeReader(code);
        var decoder = Decoder.Create(is64Bit ? 64 : 32, codeReader);
        decoder.IP = 0;

        var instr = new Instruction();
        bool stop = false;

        while (!stop && instructionCount < maxInstructions && decoder.IP < (ulong)code.Length)
        {
            ulong currentIp = decoder.IP;

            // Self-modifying code detection: execute from previously written address
            if (writtenAddresses.Contains(currentIp))
            {
                detectedPatterns.Add("SelfModifyingCode");
                writtenAddresses.Remove(currentIp); // only report once
            }

            executedAddresses.Add(currentIp);

            decoder.Decode(out instr);
            instructionCount++;

            switch (instr.Mnemonic)
            {
                case Mnemonic.Mov:
                    HandleMov(instr, registers, memory, writtenAddresses);
                    break;

                case Mnemonic.Xor:
                    HandleXor(instr, registers, ref xorLoopCount);
                    break;

                case Mnemonic.Add:
                    HandleAdd(instr, registers);
                    break;

                case Mnemonic.Sub:
                    HandleSub(instr, registers);
                    break;

                case Mnemonic.Push:
                    HandlePush(instr, registers, memory);
                    break;

                case Mnemonic.Pop:
                    HandlePop(instr, registers, memory);
                    break;

                case Mnemonic.Call:
                    if (HandleCall(instr, registers, interceptedApis))
                    {
                        // API was intercepted — do not follow the call, just continue
                    }
                    // For non-intercepted calls, we skip (no call stack simulation)
                    break;

                case Mnemonic.Ret:
                case Mnemonic.Retf:
                    // Stop emulation on return (simple heuristic)
                    stop = true;
                    break;

                case Mnemonic.Jmp:
                    if (!HandleJmp(instr, registers, decoder, code))
                    {
                        stop = true;
                    }
                    break;

                case Mnemonic.Int:
                    HandleInt(instr, detectedPatterns);
                    break;

                default:
                    // Unknown or privileged instructions — skip
                    break;
            }
        }

        // Detect encrypted loops: XOR operations with counter (xorLoopCount > 3)
        if (xorLoopCount > 3)
        {
            detectedPatterns.Add("EncryptedLoop");
        }

        // Collect all intercepted APIs into patterns
        foreach (var api in interceptedApis.Distinct())
        {
            detectedPatterns.Add($"ApiCall:{api}");
        }

        bool isSuspicious = interceptedApis.Count > 0
            || detectedPatterns.Contains("SelfModifyingCode")
            || xorLoopCount > 3;

        return new EmulationSummary(
            instructionCount,
            interceptedApis.Count,
            isSuspicious,
            detectedPatterns.Distinct().ToList());
    }

    private static bool DetectIs64Bit(byte[] code)
    {
        // Check first 10 bytes for REX prefix (0x48-0x4F range)
        int limit = Math.Min(10, code.Length);
        for (int i = 0; i < limit; i++)
        {
            if (code[i] >= 0x48 && code[i] <= 0x4F)
            {
                return true;
            }
        }
        return false;
    }

    // ────────────────────────────────────────────────────────────
    // Instruction handlers
    // ────────────────────────────────────────────────────────────

    private static void HandleMov(
        in Instruction instr,
        Dictionary<Register, ulong> registers,
        Dictionary<ulong, byte> memory,
        HashSet<ulong> writtenAddresses)
    {
        if (instr.OpCount != 2)
        {
            return;
        }

        ulong value = ReadOperandValue(instr, 1, registers, memory);

        var destKind = instr.Op0Kind;
        if (destKind == OpKind.Register)
        {
            registers[instr.Op0Register] = value;
        }
        else if (destKind == OpKind.Memory)
        {
            ulong addr = EffectiveAddress(instr, registers);
            StoreToMemory(memory, addr, value, instr.MemorySize, writtenAddresses);
        }
    }

    private static void HandleXor(
        in Instruction instr,
        Dictionary<Register, ulong> registers,
        ref int xorLoopCount)
    {
        if (instr.OpCount != 2)
        {
            return;
        }

        ulong lhs = ReadOperandValue(instr, 0, registers, new Dictionary<ulong, byte>());
        ulong rhs = ReadOperandValue(instr, 1, registers, new Dictionary<ulong, byte>());
        ulong result = lhs ^ rhs;

        if (instr.Op0Kind == OpKind.Register)
        {
            registers[instr.Op0Register] = result;
        }

        // Heuristic: XOR of non-zero values with register that looks like a counter
        if (rhs != 0 && lhs != rhs)
        {
            xorLoopCount++;
        }
    }

    private static void HandleAdd(in Instruction instr, Dictionary<Register, ulong> registers)
    {
        if (instr.OpCount != 2)
        {
            return;
        }

        ulong lhs = ReadOperandValue(instr, 0, registers, new Dictionary<ulong, byte>());
        ulong rhs = ReadOperandValue(instr, 1, registers, new Dictionary<ulong, byte>());

        if (instr.Op0Kind == OpKind.Register)
        {
            registers[instr.Op0Register] = lhs + rhs;
        }
    }

    private static void HandleSub(in Instruction instr, Dictionary<Register, ulong> registers)
    {
        if (instr.OpCount != 2)
        {
            return;
        }

        ulong lhs = ReadOperandValue(instr, 0, registers, new Dictionary<ulong, byte>());
        ulong rhs = ReadOperandValue(instr, 1, registers, new Dictionary<ulong, byte>());

        if (instr.Op0Kind == OpKind.Register)
        {
            registers[instr.Op0Register] = lhs - rhs;
        }
    }

    private static void HandlePush(
        in Instruction instr,
        Dictionary<Register, ulong> registers,
        Dictionary<ulong, byte> memory)
    {
        ulong value = ReadOperandValue(instr, 0, registers, memory);

        registers.TryGetValue(Register.RSP, out ulong rsp);
        rsp -= 8;
        registers[Register.RSP] = rsp;

        // Write 8 bytes to stack
        for (int i = 0; i < 8; i++)
        {
            memory[rsp + (ulong)i] = (byte)((value >> (i * 8)) & 0xFF);
        }
    }

    private static void HandlePop(
        in Instruction instr,
        Dictionary<Register, ulong> registers,
        Dictionary<ulong, byte> memory)
    {
        registers.TryGetValue(Register.RSP, out ulong rsp);

        ulong value = 0;
        for (int i = 0; i < 8; i++)
        {
            if (memory.TryGetValue(rsp + (ulong)i, out byte b))
            {
                value |= (ulong)b << (i * 8);
            }
        }

        rsp += 8;
        registers[Register.RSP] = rsp;

        if (instr.Op0Kind == OpKind.Register)
        {
            registers[instr.Op0Register] = value;
        }
    }

    private static bool HandleCall(
        in Instruction instr,
        Dictionary<Register, ulong> registers,
        List<string> interceptedApis)
    {
        ulong target = 0;

        if (instr.Op0Kind == OpKind.NearBranch16
            || instr.Op0Kind == OpKind.NearBranch32
            || instr.Op0Kind == OpKind.NearBranch64)
        {
            target = instr.NearBranchTarget;
        }
        else if (instr.Op0Kind == OpKind.Register)
        {
            registers.TryGetValue(instr.Op0Register, out target);
        }

        if (ApiHookTable.TryGetValue(target, out string? apiName))
        {
            interceptedApis.Add(apiName);
            return true;
        }

        return false;
    }

    private static bool HandleJmp(
        in Instruction instr,
        Dictionary<Register, ulong> registers,
        Decoder decoder,
        byte[] code)
    {
        ulong target = 0;
        bool hasTarget = false;

        if (instr.Op0Kind == OpKind.NearBranch16
            || instr.Op0Kind == OpKind.NearBranch32
            || instr.Op0Kind == OpKind.NearBranch64)
        {
            target = instr.NearBranchTarget;
            hasTarget = true;
        }
        else if (instr.Op0Kind == OpKind.Register)
        {
            registers.TryGetValue(instr.Op0Register, out target);
            hasTarget = true;
        }

        if (hasTarget && target < (ulong)code.Length)
        {
            decoder.IP = target;
            return true;
        }

        // Jump outside code range — stop emulation
        return false;
    }

    private static void HandleInt(in Instruction instr, List<string> detectedPatterns)
    {
        if (instr.OpCount > 0 && instr.Op0Kind == OpKind.Immediate8)
        {
            byte vector = (byte)instr.Immediate8;
            if (vector == 3)
            {
                detectedPatterns.Add("Breakpoint");
            }
            else if (vector == 0x80)
            {
                detectedPatterns.Add("LinuxSyscall");
            }
        }
    }

    // ────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────

    private static ulong ReadOperandValue(
        in Instruction instr,
        int opIndex,
        Dictionary<Register, ulong> registers,
        Dictionary<ulong, byte> memory)
    {
        var kind = opIndex == 0 ? instr.Op0Kind : instr.Op1Kind;

        return kind switch
        {
            OpKind.Register => registers.TryGetValue(
                opIndex == 0 ? instr.Op0Register : instr.Op1Register,
                out ulong v) ? v : 0,
            OpKind.Immediate8 => instr.Immediate8,
            OpKind.Immediate8to16 => (ulong)(long)instr.Immediate8to16,
            OpKind.Immediate8to32 => (ulong)(long)instr.Immediate8to32,
            OpKind.Immediate8to64 => (ulong)(long)instr.Immediate8to64,
            OpKind.Immediate16 => instr.Immediate16,
            OpKind.Immediate32 => instr.Immediate32,
            OpKind.Immediate32to64 => (ulong)(long)instr.Immediate32to64,
            OpKind.Immediate64 => instr.Immediate64,
            OpKind.Memory => ReadFromMemory(memory, EffectiveAddress(instr, registers), instr.MemorySize),
            _ => 0,
        };
    }

    private static ulong EffectiveAddress(in Instruction instr, Dictionary<Register, ulong> registers)
    {
        ulong addr = instr.MemoryDisplacement64;

        if (instr.MemoryBase != Register.None)
        {
            registers.TryGetValue(instr.MemoryBase, out ulong baseVal);
            addr += baseVal;
        }

        if (instr.MemoryIndex != Register.None)
        {
            registers.TryGetValue(instr.MemoryIndex, out ulong indexVal);
            addr += indexVal * (ulong)instr.MemoryIndexScale;
        }

        return addr;
    }

    private static ulong ReadFromMemory(Dictionary<ulong, byte> memory, ulong addr, MemorySize size)
    {
        int byteCount = size switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => 1,
            MemorySize.UInt16 or MemorySize.Int16 => 2,
            MemorySize.UInt32 or MemorySize.Int32 => 4,
            _ => 8,
        };

        ulong value = 0;
        for (int i = 0; i < byteCount; i++)
        {
            if (memory.TryGetValue(addr + (ulong)i, out byte b))
            {
                value |= (ulong)b << (i * 8);
            }
        }
        return value;
    }

    private static void StoreToMemory(
        Dictionary<ulong, byte> memory,
        ulong addr,
        ulong value,
        MemorySize size,
        HashSet<ulong> writtenAddresses)
    {
        int byteCount = size switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => 1,
            MemorySize.UInt16 or MemorySize.Int16 => 2,
            MemorySize.UInt32 or MemorySize.Int32 => 4,
            _ => 8,
        };

        for (int i = 0; i < byteCount; i++)
        {
            ulong a = addr + (ulong)i;
            memory[a] = (byte)((value >> (i * 8)) & 0xFF);
            writtenAddresses.Add(a);
        }
    }
}

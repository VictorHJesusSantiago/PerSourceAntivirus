import "pe"
import "math"

rule EICAR_Test_File : malicious
{
    meta:
        description = "Detects the standard EICAR antivirus test file"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download_Execute : suspicious
{
    meta:
        description = "PowerShell command that downloads and executes remote content"
    strings:
        $iex        = "IEX" nocase
        $invoke_exp = "Invoke-Expression" nocase
        $download1  = "DownloadString" nocase
        $download2  = "DownloadFile" nocase
        $webclient  = "Net.WebClient" nocase
        $encoded    = "-EncodedCommand" nocase
        $enc        = "-enc " nocase
        $bypass     = "-ExecutionPolicy Bypass" nocase
    condition:
        (($iex or $invoke_exp) and ($webclient or $download1 or $download2))
        or $encoded or $enc or $bypass
}

rule Suspicious_Office_Macro_AutoExec : suspicious
{
    meta:
        description = "Office macro that auto-executes and spawns a shell"
    strings:
        $auto1  = "AutoOpen" nocase
        $auto2  = "AutoExec" nocase
        $auto3  = "Document_Open" nocase
        $auto4  = "Workbook_Open" nocase
        $shell1 = "Shell(" nocase
        $shell2 = "WScript.Shell" nocase
        $shell3 = "powershell" nocase
    condition:
        any of ($auto*) and any of ($shell*)
}

rule Possible_Packed_Executable : suspicious
{
    meta:
        description = "PE file containing a section with very high entropy, indicating packing or encryption"
    condition:
        pe.is_pe and
        for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.5
        )
}

rule Suspicious_WindowsAPI_ProcessInjection : suspicious
{
    meta:
        description = "Executable importing API combinations commonly used for process injection"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii
        $api5 = "SetThreadContext" ascii
    condition:
        pe.is_pe and 2 of ($api*)
}

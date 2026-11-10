/*
    Generic PowerShell & .NET Loader Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Modified:    2026-11-10
    Reference:   https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
                 https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/

    These rules target scripted loaders (PowerShell cradles, HTA wrappers,
    .NET Assembly.Load patterns) rather than the shellcode they carry —
    shellcode rules are in cs_shellcode_stagers.yar.

    NOTE: These patterns are NOT Cobalt Strike specific.  They match
    generic loader techniques shared by CS, Empire, PowerSploit, Covenant,
    and other offensive toolkits.  Rules are named Generic_* accordingly.

    Detection layers:
      1. PowerShell cradle templates (IEX download, encoded command)
      2. .NET in-memory assembly loading patterns
      3. HTA / VBScript wrappers (there is no VBA macro rule yet)

    Only Generic_DotNet_Assembly_Loader skips files that start with an MZ
    header: compiled .NET assemblies (mscorlib, System.XML, ...) and
    native DLLs legitimately contain the same API and type names (25
    benign Windows matches before the skip, 0 after). The PowerShell and
    HTA rules deliberately still scan PE files: a public Cobalt Strike
    4.10 test Beacon (dissect.cobaltstrike "guardrails_beacon") matched
    the PowerShell rule as a PE, and neither rule had benign PE matches.
*/

rule Generic_PowerShell_Obfuscated_Loader : hunt
{
    meta:
        description = "Obfuscated PowerShell download cradle — matches CS, Empire, PowerSploit, Covenant, and similar"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "medium"
        tlp         = "white"

    strings:
        $flag_nop     = "-nop" ascii wide nocase
        $flag_hidden  = "-w hidden" ascii wide nocase
        $flag_enc     = "-encodedcommand" ascii wide nocase
        $flag_enc_s   = "-enc " ascii wide nocase
        $flag_ep      = "-ep bypass" ascii wide nocase
        $flag_ep2     = "-exec bypass" ascii wide nocase

        $iex_wc    = "IEX" ascii wide nocase fullword
        $dl_string = "downloadstring" ascii wide nocase
        $webclient = "net.webclient" ascii wide nocase
        $new_obj   = "new-object" ascii wide nocase

        $invoke_expr   = "Invoke-Expression" ascii wide nocase

    condition:
        filesize < 2MB and
        (
            ($flag_nop and $flag_hidden and ($flag_enc or $flag_enc_s)) or
            ($iex_wc and $dl_string and $webclient) or
            ($invoke_expr and $dl_string and $new_obj) or
            ($flag_nop and $flag_hidden and ($flag_ep or $flag_ep2) and $iex_wc)
        )
}


rule Generic_DotNet_Assembly_Loader : hunt
{
    meta:
        description = "In-memory .NET assembly loading patterns in scripts — matches SharpSploit, offensive PowerShell, and similar loaders"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.mandiant.com/resources/defining-cobalt-strike-components"
        severity    = "medium"
        tlp         = "white"

    strings:
        $asm_load     = "System.Reflection.Assembly" ascii wide nocase
        $asm_load2    = "Assembly.Load" ascii wide nocase
        $marshal      = "System.Runtime.InteropServices.Marshal" ascii wide nocase
        $from_base64  = "FromBase64String" ascii wide nocase
        $convert      = "[Convert]::" ascii wide nocase

        $valloc       = "VirtualAlloc" ascii wide
        $create_thrd  = "CreateThread" ascii wide

        $delegate     = "GetDelegateForFunctionPointer" ascii wide
        $pinvoke      = "DllImport" ascii wide

    condition:
        filesize < 5MB and
        uint16(0) != 0x5A4D and
        (
            ($asm_load and $from_base64) or
            ($asm_load2 and $convert) or
            ($valloc and $create_thrd and ($delegate or $pinvoke)) or
            ($marshal and $valloc and $from_base64)
        )
}


rule Generic_HTA_VBS_Loader : hunt
{
    meta:
        description = "HTA / VBScript stager wrapper — matches CS, generic malware droppers, and similar"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/"
        severity    = "medium"
        tlp         = "white"

    strings:
        /* <script ... language = "VBScript"> with single, double or no
           quotes, other attributes first, and spaces around "=". Bounded
           so the regex cannot run away. */
        $hta_tag      = /<script[^>]{0,64}language[ \t]{0,4}=[ \t]{0,4}["']?vbscript/ ascii wide nocase
        $shell_run    = "Wscript.Shell" ascii wide nocase
        $shell_exec   = ".Run" ascii wide nocase
        $powershell   = "powershell" ascii wide nocase

        $activex      = "CreateObject" ascii wide nocase

        /* Bounded Chr concatenation — 1-3 digits, at most 16 spaces/tabs each side of & */
        $chr_concat   = /Chr\(\d{1,3}\)[ \t]{0,16}&[ \t]{0,16}Chr\(\d{1,3}\)/ ascii wide nocase

        /* MSXML Base64 decode context — replaces the atomless regex */
        $b64_type = "bin.base64" ascii wide nocase
        $typed_value = "nodeTypedValue" ascii wide nocase

    condition:
        filesize < 2MB and
        (
            ($hta_tag and $powershell and ($shell_run or $shell_exec)) or
            ($activex and $shell_run and $shell_exec and $chr_concat) or
            ($hta_tag and $activex and $b64_type and $typed_value)
        )
}

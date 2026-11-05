/*
    Generic PowerShell & .NET Loader Detection
    Author:      struttonpigeon
    Date:        2026-11-05
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
      3. HTA / VBS / VBA macro wrappers
*/

rule Generic_PowerShell_Obfuscated_Loader
{
    meta:
        description = "Obfuscated PowerShell download cradle — matches CS, Empire, PowerSploit, Covenant, and similar"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            Generic PowerShell one-liner template used by many tools:

              powershell -nop -w hidden -encodedcommand <base64>

            or the download-and-execute variant:

              IEX ((new-object net.webclient).downloadstring('http://...'))

            The flags -nop (NoProfile) and -w hidden (WindowStyle Hidden)
            are nearly universal in CS PowerShell payloads.
        */
        $flag_nop     = "-nop" ascii nocase
        $flag_hidden  = "-w hidden" ascii nocase
        $flag_enc     = "-encodedcommand" ascii nocase
        $flag_enc_s   = "-enc " ascii nocase
        $flag_ep      = "-ep bypass" ascii nocase
        $flag_ep2     = "-exec bypass" ascii nocase

        /*
            The download cradle pattern — IEX + WebClient or
            Invoke-Expression + DownloadString.
        */
        $iex_wc    = "IEX" ascii nocase fullword
        $dl_string = "downloadstring" ascii nocase
        $webclient = "net.webclient" ascii nocase
        $new_obj   = "new-object" ascii nocase

        /* Invoke-Expression is common across many offensive toolkits: */
        $invoke_expr   = "Invoke-Expression" ascii nocase

    condition:
        filesize < 2MB and
        (
            // Encoded command variant
            ($flag_nop and $flag_hidden and ($flag_enc or $flag_enc_s)) or
            // Download cradle variant
            ($iex_wc and $dl_string and $webclient) or
            ($invoke_expr and $dl_string and $new_obj) or
            // Combined flags typical of CS
            ($flag_nop and $flag_hidden and ($flag_ep or $flag_ep2) and $iex_wc)
        )
}


rule Generic_DotNet_Assembly_Loader
{
    meta:
        description = "In-memory .NET assembly loading patterns in scripts — matches SharpSploit, offensive PowerShell, and similar loaders"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.mandiant.com/resources/defining-cobalt-strike-components"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            Reflective .NET assembly loading API references.
            These appear in loader scripts (PowerShell, C#) that call:
              [System.Reflection.Assembly]::Load(byte[])
              [System.Runtime.InteropServices.Marshal]::Copy(...)
        */
        $asm_load     = "System.Reflection.Assembly" ascii nocase
        $asm_load2    = "Assembly.Load" ascii nocase
        $marshal      = "System.Runtime.InteropServices.Marshal" ascii nocase
        $from_base64  = "FromBase64String" ascii nocase
        $convert      = "[Convert]::" ascii nocase

        /*
            VirtualAlloc + copy shellcode pattern in C# / PowerShell:
        */
        $valloc       = "VirtualAlloc" ascii
        $create_thrd  = "CreateThread" ascii

        /*
            Delegate-based shellcode execution — common in CS .NET loaders:
        */
        $delegate     = "GetDelegateForFunctionPointer" ascii
        $pinvoke      = "DllImport" ascii

    condition:
        filesize < 5MB and
        (
            // .NET reflection loading path
            ($asm_load and $from_base64) or
            ($asm_load2 and $convert) or
            // Shellcode injection via P/Invoke
            ($valloc and $create_thrd and ($delegate or $pinvoke)) or
            // Marshal-based memory manipulation
            ($marshal and $valloc and $from_base64)
        )
}


rule Generic_HTA_VBS_Loader
{
    meta:
        description = "HTA / VBScript stager wrapper — matches CS, generic malware droppers, and similar"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            CS HTA payloads use the following template structure:
            <script language="VBScript">
              ... Shell.Run "powershell ..."
            or
              ... CreateObject("Wscript.Shell").Run ...
        */
        $hta_tag      = "<script language=\"VBScript\">" ascii nocase
        $shell_run    = "Wscript.Shell" ascii nocase
        $shell_exec   = ".Run" ascii nocase
        $powershell   = "powershell" ascii nocase

        /*
            The ActiveXObject wrapper for COM-based execution:
        */
        $activex      = "CreateObject" ascii nocase

        /*
            CS-generated VBScript often includes Chr() concatenation
            to build the PowerShell command at runtime:
        */
        $chr_concat   = /Chr\(\d+\)\s*&\s*Chr\(\d+\)/ ascii nocase

        /*
            Embedded Base64 payload — HTA files often contain a large
            Base64 blob that decodes to shellcode.
            NOTE: This regex has no literal atom so YARA cannot use
            Aho-Corasick acceleration; it relies on other literal strings
            in the condition to avoid a full-file scan.  May also match
            minified JavaScript, so always require additional context.
        */
        $b64_blob     = /[A-Za-z0-9+\/]{500,}={0,2}/ ascii

    condition:
        filesize < 2MB and
        (
            ($hta_tag and $powershell and ($shell_run or $shell_exec)) or
            ($activex and $shell_exec and $chr_concat and $b64_blob) or
            ($hta_tag and $b64_blob and $activex)
        )
}

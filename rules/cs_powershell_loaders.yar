/*
    Cobalt Strike — PowerShell & .NET Loader Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
                 https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/

    Cobalt Strike ships several payload generators that produce PowerShell
    and .NET delivery scripts.  These rules target the scripted loaders
    (PowerShell cradles, HTA wrappers, .NET Assembly.Load patterns) rather
    than the shellcode they carry — shellcode rules are in
    cs_shellcode_stagers.yar.

    Detection layers:
      1. PowerShell cradle templates (IEX download, encoded command)
      2. .NET in-memory assembly loading patterns
      3. HTA / VBS / VBA macro wrappers
*/

rule CobaltStrike_PowerShell_Cradle
{
    meta:
        description = "Cobalt Strike default PowerShell download cradle patterns"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            CS generates PowerShell one-liners that follow this template:

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
        $iex_wc    = "IEX" ascii nocase
        $dl_string = "downloadstring" ascii nocase
        $webclient = "net.webclient" ascii nocase
        $new_obj   = "new-object" ascii nocase

        /*
            CS-specific: the PowerShell payload often includes a
            Base64-decoded shellcode injector using these .NET types:
        */
        $invoke_expr   = "Invoke-Expression" ascii nocase
        $start_process = "Start-Process" ascii nocase

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


rule CobaltStrike_DotNet_Assembly_Loader
{
    meta:
        description = "In-memory .NET assembly loading — Cobalt Strike execute-assembly technique"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.mandiant.com/resources/defining-cobalt-strike-components"
        severity    = "high"
        tlp         = "white"

    strings:
        /*
            Cobalt Strike's execute-assembly command loads a .NET assembly
            reflectively.  The PowerShell / C# loader uses these APIs:

            [System.Reflection.Assembly]::Load(byte[])
            [System.Runtime.InteropServices.Marshal]::Copy(...)

            These appear in the loader script or compiled stub.
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
        $memcpy       = "Copy-Memory" ascii nocase
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


rule CobaltStrike_HTA_VBS_Loader
{
    meta:
        description = "Cobalt Strike HTA / VBScript stager wrapper patterns"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/"
        severity    = "high"
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
            Embedded Base64 payload — CS HTA files contain a large
            Base64 blob that decodes to the stager shellcode.
            Match a B64 blob of at least 500 characters (typical CS payload).
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

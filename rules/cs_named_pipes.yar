/*
    Cobalt Strike — Named Pipe Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Modified:    2026-11-10
    Reference:   https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
                 https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_peer-to-peer.htm

    Cobalt Strike uses named pipes for:
      1. SMB Beacon lateral movement (peer-to-peer comms)
      2. Post-exploitation job output (fork & run)
      3. SSH agent forwarding

    Default pipe names are well-known and rarely customised by less
    sophisticated operators.  These rules catch the default names in
    binaries, scripts, and memory dumps.

    NOTE: Named pipes alone are weak indicators — legitimate software also
    uses them.  These rules are most useful as supporting evidence alongside
    other CS-specific detections.
*/

rule CobaltStrike_Named_Pipes_Default : hunt
{
    meta:
        description = "Default Cobalt Strike named pipe patterns in files or memory"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "medium"
        tlp         = "white"

    strings:
        $pipe_msagent   = "\\\\.\\pipe\\msagent_"   ascii wide nocase
        $pipe_msse      = "\\\\.\\pipe\\MSSE-"       ascii wide nocase
        $pipe_postex    = "\\\\.\\pipe\\postex_"     ascii wide nocase
        $pipe_status    = "\\\\.\\pipe\\status_"     ascii wide nocase

    condition:
        filesize < 50MB and
        (
            (($pipe_msagent or $pipe_msse) and any of ($pipe_postex, $pipe_status)) or
            ($pipe_msagent and $pipe_msse)
        )
}


rule CobaltStrike_Named_Pipes_Strings_Only : hunt
{
    meta:
        description = "Cobalt Strike pipe name strings without the UNC prefix — catches malleable C2 configs and scripts"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_peer-to-peer.htm"
        severity    = "medium"
        tlp         = "white"

    strings:
        $p1 = "msagent_"   ascii wide nocase
        $p2 = "postex_"    ascii wide nocase
        $p3 = "MSSE-"      ascii wide

        $directive_smb     = "set pipename"    ascii wide nocase
        $directive_tcp     = "set tcp_port"    ascii wide nocase
        $directive_spawnto = "set spawnto_x"   ascii wide nocase

    condition:
        (
            (2 of ($p1, $p2, $p3)) or
            ($directive_smb and any of ($p*)) or
            (all of ($directive_*))
        )
}

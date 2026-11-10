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

    WHERE THESE CAN FIRE: in a beacon DLL the pipe names live inside the
    XOR-encoded config block, and the default Artifact Kit assembles the
    "\\.\pipe\" prefix at runtime, so the full UNC strings below rarely
    exist in files on disk. CobaltStrike_Named_Pipes_Default is mainly
    useful on decoded memory. CobaltStrike_ArtifactKit_Pipe_Format
    targets the format string that IS present in default Artifact Kit
    executables; it is file-only (MZ header and size cap), so it does not
    fire on live-process scans, where filesize is undefined.
*/

rule CobaltStrike_ArtifactKit_Pipe_Format : hunt
{
    meta:
        description = "Default Artifact Kit pipe-name format string (MSSE-<n>-server) in a PE file"
        author      = "struttonpigeon"
        date        = "2026-11-10"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "high"
        tlp         = "white"

    strings:
        $fmt = "MSSE-%d-server" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and $fmt
}


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
        /* No filesize cap: this rule targets memory. A cap silently
           skipped dumps >= 50MB, and filesize is undefined when scanning
           a running process (yara <rules> <pid>), which made the whole
           condition false there. */
        (($pipe_msagent or $pipe_msse) and any of ($pipe_postex, $pipe_status)) or
        ($pipe_msagent and $pipe_msse)
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

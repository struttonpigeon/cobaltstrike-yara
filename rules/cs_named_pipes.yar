/*
    Cobalt Strike — Named Pipe Detection
    Author:      struttonpigeon
    Date:        2026-11-05
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

rule CobaltStrike_Named_Pipes_Default
{
    meta:
        description = "Default Cobalt Strike named pipe patterns in files or memory"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "high"
        tlp         = "white"

    strings:
        /*
            SMB Beacon default pipe names.
            The "msagent_" prefix is CS 4.x default for SMB beacons.
            "MSSE-" is the CS 3.x / early 4.x default.
        */
        $pipe_msagent   = "\\\\.\\pipe\\msagent_"   ascii nocase
        $pipe_msse      = "\\\\.\\pipe\\MSSE-"       ascii nocase

        /*
            Post-exploitation (fork & run) default pipe names.
            These are used when CS injects a temporary process to run
            a post-ex job (hashdump, screenshot, keylogger, etc.).
            The "postex_" prefix has been default since CS 4.x.
            "status_" and "postex_ssh_" are used for specific job types.
        */
        $pipe_postex     = "\\\\.\\pipe\\postex_"     ascii nocase
        $pipe_status     = "\\\\.\\pipe\\status_"     ascii nocase
        $pipe_postex_ssh = "\\\\.\\pipe\\postex_ssh_" ascii nocase

        /*
            Older defaults and common customisations seen in the wild.
            "msagent_##" where ## is random hex — pattern match.
        */
        $pipe_old_1 = "\\\\.\\pipe\\win_svc" ascii nocase
        $pipe_old_2 = "\\\\.\\pipe\\ntsvcs"   ascii nocase

    condition:
        filesize < 50MB and
        2 of ($pipe_*)
}


rule CobaltStrike_Named_Pipes_Strings_Only
{
    meta:
        description = "Cobalt Strike pipe name strings without the UNC prefix — catches malleable C2 configs and scripts"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_peer-to-peer.htm"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            In malleable C2 profiles and some scripts the pipe name
            appears without the full UNC path, just the name portion.
        */
        $p1 = "msagent_"   ascii nocase
        $p2 = "postex_"    ascii nocase
        $p3 = "postex_ssh" ascii nocase
        $p4 = "MSSE-"      ascii

        /*
            The "pipename" directive in malleable C2 profiles.
            This is a strong indicator when found in a .profile file.
        */
        $directive_smb    = "set pipename"    ascii nocase
        $directive_tcp    = "set tcp_port"    ascii nocase
        $directive_spawnto = "set spawnto_x"  ascii nocase

    condition:
        filesize < 1MB and
        (
            (2 of ($p*)) or
            ($directive_smb and any of ($p*)) or
            (all of ($directive_*))
        )
}

/*
    Cobalt Strike — Beacon Configuration Block Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Modified:    2026-11-10
    Reference:   https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/
                 https://github.com/Sentinel-One/CobaltStrikeParser

    Every Cobalt Strike beacon embeds a configuration block that tells it
    where to call home, how often to sleep, which named pipes to use, etc.

    The supported XOR keys are 0x69 and 0x2E. These byte patterns alone
    do not establish a product version.

    Each config entry follows the TLV layout:
        setting_id (2 bytes, big-endian)
        data_type  (2 bytes): 0x0001 = short, 0x0002 = int, 0x0003 = blob
        length     (2 bytes): byte length of the value field
        value      (variable)

    The core rules match five consecutive ordered TLVs (settings 1-5):
    BeaconType, Port, SleepTime, MaxGetSize, Jitter.
    Total prefix: 8+8+10+10+8 = 44 bytes.
*/

rule CobaltStrike_Beacon_Config_XOR69 : core
{
    meta:
        description = "Ordered Beacon config prefix XOR-encoded with key 0x69"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "high"
        tlp         = "white"

    strings:
        // Five consecutive TLVs: type, port, sleep, max-get, jitter.
        // BeaconType value byte is wildcarded to cover all types (HTTP, SMB, TCP, HTTPS, bind-TCP, external C2).
        $config = {
            69 68 69 68 69 6B 69 ??
            69 6B 69 68 69 6B ?? ??
            69 6A 69 6B 69 6D ?? ?? ?? ??
            69 6D 69 6B 69 6D ?? ?? ?? ??
            69 6C 69 68 69 6B ?? ??
        }

    condition:
        $config
}


rule CobaltStrike_Beacon_Config_XOR2E : core
{
    meta:
        description = "Ordered Beacon config prefix XOR-encoded with key 0x2E"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/"
        severity    = "high"
        tlp         = "white"

    strings:
        // Five consecutive TLVs: type, port, sleep, max-get, jitter.
        // BeaconType value byte is wildcarded to cover all types.
        $config = {
            2E 2F 2E 2F 2E 2C 2E ??
            2E 2C 2E 2F 2E 2C ?? ??
            2E 2D 2E 2C 2E 2A ?? ?? ?? ??
            2E 2A 2E 2C 2E 2A ?? ?? ?? ??
            2E 2B 2E 2F 2E 2C ?? ??
        }

    condition:
        $config
}


rule CobaltStrike_Beacon_Config_Decoded : core
{
    meta:
        description = "Ordered decoded Beacon config prefix with five consecutive settings"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "high"
        tlp         = "white"

    strings:
        // Five consecutive TLVs: type, port, sleep, max-get, jitter.
        // BeaconType value byte is wildcarded to cover all types.
        $config = {
            00 01 00 01 00 02 00 ??
            00 02 00 01 00 02 ?? ??
            00 03 00 02 00 04 ?? ?? ?? ??
            00 04 00 02 00 04 ?? ?? ?? ??
            00 05 00 01 00 02 ?? ??
        }

    condition:
        $config
}


rule CobaltStrike_Beacon_Config_Strings : hunt
{
    meta:
        description = "Plaintext strings commonly found in decoded beacon configs or memory — supporting evidence, not standalone"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "medium"
        tlp         = "white"

    strings:
        /* Default malleable C2 profile indicators */
        $c2_submit  = "/submit.php" ascii wide
        $c2_visit   = "/visit.js" ascii wide
        $c2_pixel   = "/__utm.gif" ascii wide
        $c2_jquery  = "/jquery-3" ascii wide

        /* Spawnto default values — processes Cobalt Strike injects into */
        $spawn_x86 = "%windir%\\syswow64\\rundll32.exe" ascii wide nocase
        $spawn_x64 = "%windir%\\sysnative\\rundll32.exe" ascii wide nocase

    condition:
        (any of ($spawn_*) and any of ($c2_*)) or
        (CobaltStrike_Beacon_Config_Decoded and any of ($c2_*))
}

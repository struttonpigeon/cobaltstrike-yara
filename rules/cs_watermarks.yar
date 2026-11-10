/*
    Beacon setting 37 (0x0025) holds a four-byte big-endian watermark.
    Author: struttonpigeon
    Date: 2026-11-05
    Modified: 2026-11-10

    Every rule in this file anchors the watermark TLV to the same
    five-setting ordered prefix used by cs_beacon_config.yar. The
    watermark must start within 4042 bytes after the end of that prefix
    (44 prefix + 4042 gap + 10 watermark = 4096 bytes). This is a
    heuristic window, not the config block size: the decoded blocks in
    eight public CS 4.2-4.12 test Beacons were 6144 bytes, and in all
    eight the watermark fell inside this window (see
    samples/known_hashes.txt).
    The window is relative to the prefix, not to the start of the input.
    This is a candidate-field heuristic; it does not parse every
    intervening TLV or prove a field boundary.

    A standalone 10-byte watermark TLV is deliberately NOT matched: it
    is short enough to collide with unrelated data.

    The cracked-watermark rule matches well-known values from leaked
    builds. Scan with -s to see candidate regions. XOR the last four
    bytes with the indicated key for encoded matches.

    A watermark does not establish licensing status or authorization.
*/

rule CobaltStrike_Watermark_Cracked_Common : hunt
{
    meta:
        description = "Config prefix followed by a well-known cracked/leaked watermark (0x12345678 or 0x5109BF6D) — decoded, XOR 0x69, and XOR 0x2E"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://michaelkoczwara.medium.com/cobalt-strike-watermark-analysis-bc0aecec28cd"
        severity    = "critical"
        tlp         = "white"

    strings:
        /* 305419896 (0x12345678) and 1359593325 (0x5109BF6D) */
        $wm_dec = {
            00 01 00 01 00 02 00 ??
            00 02 00 01 00 02 ?? ??
            00 03 00 02 00 04 ?? ?? ?? ??
            00 04 00 02 00 04 ?? ?? ?? ??
            00 05 00 01 00 02 ?? ??
            [0-4042]
            00 25 00 02 00 04 ( 12 34 56 78 | 51 09 BF 6D )
        }

        $wm_x69 = {
            69 68 69 68 69 6B 69 ??
            69 6B 69 68 69 6B ?? ??
            69 6A 69 6B 69 6D ?? ?? ?? ??
            69 6D 69 6B 69 6D ?? ?? ?? ??
            69 6C 69 68 69 6B ?? ??
            [0-4042]
            69 4C 69 6B 69 6D ( 7B 5D 3F 11 | 38 60 D6 04 )
        }

        $wm_x2e = {
            2E 2F 2E 2F 2E 2C 2E ??
            2E 2C 2E 2F 2E 2C ?? ??
            2E 2D 2E 2C 2E 2A ?? ?? ?? ??
            2E 2A 2E 2C 2E 2A ?? ?? ?? ??
            2E 2B 2E 2F 2E 2C ?? ??
            [0-4042]
            2E 0B 2E 2C 2E 2A ( 3C 1A 78 56 | 7F 27 91 43 )
        }

    condition:
        any of ($wm_*)
}


rule CobaltStrike_Watermark_Zero : hunt
{
    meta:
        description = "Config prefix followed by watermark 0 — trial or unset value; not by itself proof of a cracked build"
        author      = "struttonpigeon"
        date        = "2026-11-10"
        modified    = "2026-11-10"
        reference   = "https://michaelkoczwara.medium.com/cobalt-strike-watermark-analysis-bc0aecec28cd"
        severity    = "high"
        tlp         = "white"

    strings:
        $wm0_dec = {
            00 01 00 01 00 02 00 ??
            00 02 00 01 00 02 ?? ??
            00 03 00 02 00 04 ?? ?? ?? ??
            00 04 00 02 00 04 ?? ?? ?? ??
            00 05 00 01 00 02 ?? ??
            [0-4042]
            00 25 00 02 00 04 00 00 00 00
        }

        $wm0_x69 = {
            69 68 69 68 69 6B 69 ??
            69 6B 69 68 69 6B ?? ??
            69 6A 69 6B 69 6D ?? ?? ?? ??
            69 6D 69 6B 69 6D ?? ?? ?? ??
            69 6C 69 68 69 6B ?? ??
            [0-4042]
            69 4C 69 6B 69 6D 69 69 69 69
        }

        $wm0_x2e = {
            2E 2F 2E 2F 2E 2C 2E ??
            2E 2C 2E 2F 2E 2C ?? ??
            2E 2D 2E 2C 2E 2A ?? ?? ?? ??
            2E 2A 2E 2C 2E 2A ?? ?? ?? ??
            2E 2B 2E 2F 2E 2C ?? ??
            [0-4042]
            2E 0B 2E 2C 2E 2A 2E 2E 2E 2E
        }

    condition:
        any of ($wm0_*)
}


rule CobaltStrike_Watermark_Setting_Present : hunt
{
    meta:
        description = "Candidate watermark field near a decoded Beacon config prefix"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "medium"
        tlp         = "white"

    strings:
        $candidate = {
            00 01 00 01 00 02 00 ??
            00 02 00 01 00 02 ?? ??
            00 03 00 02 00 04 ?? ?? ?? ??
            00 04 00 02 00 04 ?? ?? ?? ??
            00 05 00 01 00 02 ?? ??
            [0-4042]
            00 25 00 02 00 04 ?? ?? ?? ??
        }

    condition:
        $candidate
}


rule CobaltStrike_Watermark_XOR69 : hunt
{
    meta:
        description = "Candidate watermark field near a Beacon config prefix (XOR key 0x69)"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "medium"
        tlp         = "white"

    strings:
        $candidate = {
            69 68 69 68 69 6B 69 ??
            69 6B 69 68 69 6B ?? ??
            69 6A 69 6B 69 6D ?? ?? ?? ??
            69 6D 69 6B 69 6D ?? ?? ?? ??
            69 6C 69 68 69 6B ?? ??
            [0-4042]
            69 4C 69 6B 69 6D ?? ?? ?? ??
        }

    condition:
        $candidate
}


rule CobaltStrike_Watermark_XOR2E : hunt
{
    meta:
        description = "Candidate watermark field near a Beacon config prefix (XOR key 0x2E)"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "medium"
        tlp         = "white"

    strings:
        $candidate = {
            2E 2F 2E 2F 2E 2C 2E ??
            2E 2C 2E 2F 2E 2C ?? ??
            2E 2D 2E 2C 2E 2A ?? ?? ?? ??
            2E 2A 2E 2C 2E 2A ?? ?? ?? ??
            2E 2B 2E 2F 2E 2C ?? ??
            [0-4042]
            2E 0B 2E 2C 2E 2A ?? ?? ?? ??
        }

    condition:
        $candidate
}

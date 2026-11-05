/*
    Cobalt Strike — Watermark / License ID Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://blog.didierstevens.com/2021/11/12/cobalt-strike-understanding-payloads/
                 https://michaelkoczwara.medium.com/cobalt-strike-watermark-analysis-bc0aecec28cd

    Every licensed Cobalt Strike installation embeds a 4-byte watermark
    (license ID) in every beacon it generates.  The watermark occupies
    setting ID 0x0025 in the beacon configuration block.

    Cracked or leaked copies of Cobalt Strike reuse a small number of
    well-known watermarks.  Detecting these values is high-confidence
    evidence of an unauthorised (and almost certainly malicious) deployment.

    Legitimate red-team engagements use unique per-license watermarks that
    these rules will not match — reducing false positives on authorised use.

    Config setting TLV layout for watermark:
        00 25   — setting ID (Watermark)
        00 02   — data type (int, 4 bytes)
        00 04   — length (4 bytes)
        XX XX XX XX — the watermark value (big-endian)
*/

rule CobaltStrike_Watermark_Cracked_Common
{
    meta:
        description = "Well-known watermarks from cracked/leaked Cobalt Strike builds"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://michaelkoczwara.medium.com/cobalt-strike-watermark-analysis-bc0aecec28cd"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            Watermark 0 — the trial/unlicensed value.  Present in
            evaluation builds and some early cracked copies.
            Decoded config bytes: 00 25 00 02 00 04 00 00 00 00
        */
        $wm_zero = { 00 25 00 02 00 04 00 00 00 00 }

        /*
            Watermark 305419896 (0x12345678) — the most widely observed
            watermark from cracked CS 4.x builds circulated on underground
            forums.  Decoded config bytes: 00 25 00 02 00 04 12 34 56 78
        */
        $wm_12345678 = { 00 25 00 02 00 04 12 34 56 78 }

        /*
            Watermark 1359593325 (0x5109BF6D) — from a different leaked build,
            widely cited in public watermark lists.
        */
        $wm_5109bf6d = { 00 25 00 02 00 04 51 09 BF 6D }

    condition:
        filesize < 5MB and
        any of ($wm_*)
}


rule CobaltStrike_Watermark_XOR69
{
    meta:
        description = "Cracked watermarks in XOR-0x69 encoded config blocks"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            The same watermark setting bytes XOR'd with 0x69:

            Original:  00 25 00 02 00 04 XX XX XX XX
            XOR 0x69:  69 4C 69 6B 69 6D YY YY YY YY
        */
        $wm_zero_xor69     = { 69 4C 69 6B 69 6D 69 69 69 69 }
        $wm_12345678_xor69 = { 69 4C 69 6B 69 6D 7B 5D 3F 11 }
        $wm_5109bf6d_xor69 = { 69 4C 69 6B 69 6D 38 60 D6 04 }

    condition:
        filesize < 5MB and
        any of ($wm_*)
}


rule CobaltStrike_Watermark_XOR2E
{
    meta:
        description = "Cracked watermarks in XOR-0x2E encoded config blocks"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            Original:  00 25 00 02 00 04 XX XX XX XX
            XOR 0x2E:  2E 0B 2E 2C 2E 2A YY YY YY YY
        */
        $wm_zero_xor2e     = { 2E 0B 2E 2C 2E 2A 2E 2E 2E 2E }
        $wm_12345678_xor2e = { 2E 0B 2E 2C 2E 2A 3C 1A 78 56 }
        $wm_5109bf6d_xor2e = { 2E 0B 2E 2C 2E 2A 7F 27 91 43 }

    condition:
        filesize < 5MB and
        any of ($wm_*)
}


rule CobaltStrike_Watermark_Setting_Present
{
    meta:
        description = "Generic detection of the watermark setting field in decoded config — any value"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            The watermark setting header in a decoded config.
            Setting 0x0025, type 0x0002 (int), length 0x0004.
            This matches ALL watermarks, not just known-cracked ones.
            Lower severity — useful for hunting, not alerting.
        */
        $wm_header = { 00 25 00 02 00 04 }

        /*
            Require at least one other beacon config setting nearby
            to reduce false positives on random byte matches.
            Setting 0x0001 = BeaconType (short, length 2)
        */
        $beacon_type = { 00 01 00 01 00 02 }

        /*
            Setting 0x0003 = SleepTime (int, length 4)
        */
        $sleep_time = { 00 03 00 02 00 04 }

    condition:
        filesize < 5MB and
        $wm_header and
        ($beacon_type or $sleep_time)
}

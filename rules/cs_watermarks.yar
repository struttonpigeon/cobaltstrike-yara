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

    Config setting layout for watermark:
        00 25   — setting ID (Watermark)
        00 02   — data type (int, 4 bytes)
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
            Watermark 0 — the earliest cracked builds zero out the license.
            Decoded config bytes: 00 25 00 02 00 00 00 00
        */
        $wm_zero = { 00 25 00 02 00 00 00 00 }

        /*
            Watermark 305419896 (0x12345678) — the most widely observed
            watermark from cracked CS 4.x builds circulated on underground
            forums.  Decoded config bytes: 00 25 00 02 12 34 56 78
        */
        $wm_12345678 = { 00 25 00 02 12 34 56 78 }

        /*
            Watermark 1359593325 (0x5109BF6D) — from a different leaked build.
        */
        $wm_5109bf6d = { 00 25 00 02 51 09 BF 6D }

        /*
            Watermark 1580103824 (0x5E2B1010) — observed in multiple
            APT campaigns using cracked CS.
        */
        $wm_5e2b1010 = { 00 25 00 02 5E 2B 10 10 }

        /*
            Watermark 674054187 (0x2831B52B) — another frequently observed
            cracked-build watermark in threat intel reports.
        */
        $wm_2831b52b = { 00 25 00 02 28 31 B5 2B }

        /*
            Watermark 391144938 (0x174F7E6A) — seen in Southeast Asian
            APT campaigns.
        */
        $wm_174f7e6a = { 00 25 00 02 17 4F 7E 6A }

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

            Original:  00 25 00 02 XX XX XX XX
            XOR 0x69:  69 4C 69 6B YY YY YY YY

            Watermark 0x00000000 XOR 0x69 = 69 69 69 69
            Watermark 0x12345678 XOR 0x69 = 7B 5D 3F 11
        */
        $wm_zero_xor69     = { 69 4C 69 6B 69 69 69 69 }
        $wm_12345678_xor69 = { 69 4C 69 6B 7B 5D 3F 11 }
        $wm_5109bf6d_xor69 = { 69 4C 69 6B 38 60 D6 04 }

    condition:
        filesize < 5MB and
        any of ($wm_*_xor69)
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
            Original:  00 25 00 02 XX XX XX XX
            XOR 0x2E:  2E 0B 2E 2C YY YY YY YY

            Watermark 0x00000000 XOR 0x2E = 2E 2E 2E 2E
            Watermark 0x12345678 XOR 0x2E = 3C 1A 78 56
        */
        $wm_zero_xor2e     = { 2E 0B 2E 2C 2E 2E 2E 2E }
        $wm_12345678_xor2e = { 2E 0B 2E 2C 3C 1A 78 56 }

    condition:
        filesize < 5MB and
        any of ($wm_*_xor2e)
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
            Setting 0x0025, type 0x0002 (int), followed by any 4-byte value.
            This matches ALL watermarks, not just known-cracked ones.
            Lower severity — useful for hunting, not alerting.
        */
        $wm_header = { 00 25 00 02 }

        /*
            Require at least one other beacon config setting nearby
            to reduce false positives on random byte matches.
            Setting 0x0001 = BeaconType
        */
        $beacon_type = { 00 01 00 01 }

        /*
            Setting 0x0003 = SleepTime
        */
        $sleep_time = { 00 03 00 02 }

    condition:
        filesize < 5MB and
        $wm_header and
        ($beacon_type or $sleep_time)
}

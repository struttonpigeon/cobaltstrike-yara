/*
    Cobalt Strike — Beacon Configuration Block Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/
                 https://github.com/Sentinel-One/CobaltStrikeParser

    Every Cobalt Strike beacon embeds a configuration block that tells it
    where to call home, how often to sleep, which named pipes to use, etc.

    CS 3.x stored the config in cleartext with a 2-byte header per setting.
    CS 4.x XOR-encodes the entire config blob with a single-byte key.
    Common XOR keys observed in the wild: 0x69 and 0x2E.

    The decoded config always starts with a 2-byte setting ID (0x0001 =
    BeaconType) followed by a 2-byte data-type indicator and the value.

    These rules detect both the encoded and decoded forms.
*/

rule CobaltStrike_Beacon_Config_v4_XOR69
{
    meta:
        description = "CS4 beacon config XOR-encoded with key 0x69 — the most common default"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            When the config starts with setting 0x0001 (BeaconType), data
            type 0x0001 (short), and value 0x0000 (HTTP) or 0x0001 (HTTPS)
            or 0x0008 (DNS), the first bytes of the decoded block are:

                00 01 00 01 00 0?

            XOR 0x69 each byte:
                69 68 69 68 69 6?

            We match the XOR'd header for BeaconType = HTTP (0x0000):
                00 01 00 01 00 00  XOR 0x69 = 69 68 69 68 69 69
            and BeaconType = HTTPS (0x0001):
                00 01 00 01 00 01  XOR 0x69 = 69 68 69 68 69 68
            and BeaconType = DNS (0x0008):
                00 01 00 01 00 08  XOR 0x69 = 69 68 69 68 69 61
        */
        $cfg_http_xor69  = { 69 68 69 68 69 69 }
        $cfg_https_xor69 = { 69 68 69 68 69 68 }
        $cfg_dns_xor69   = { 69 68 69 68 69 61 }

        /*
            After BeaconType, setting 0x0002 (Port) follows with type
            0x0001 (short).  The pattern 00 02 00 01 XOR 0x69 = 69 6B 69 68.
            Then the port value in big-endian, XOR 0x69.
            Port 80  (0x0050) XOR 0x69 = 69 39
            Port 443 (0x01BB) XOR 0x69 = 68 D2
        */
        $port_80_xor69  = { 69 6B 69 68 69 39 }
        $port_443_xor69 = { 69 6B 69 68 68 [1] }

    condition:
        filesize < 5MB and
        any of ($cfg_*_xor69) and
        any of ($port_*_xor69)
}


rule CobaltStrike_Beacon_Config_v4_XOR2E
{
    meta:
        description = "CS4 beacon config XOR-encoded with key 0x2E — second most common key"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            Same logic as the 0x69 rule, but with XOR key 0x2E:
            00 01 00 01 00 00  XOR 0x2E = 2E 2F 2E 2F 2E 2E  (HTTP)
            00 01 00 01 00 01  XOR 0x2E = 2E 2F 2E 2F 2E 2F  (HTTPS)
        */
        $cfg_http_xor2e  = { 2E 2F 2E 2F 2E 2E }
        $cfg_https_xor2e = { 2E 2F 2E 2F 2E 2F }

    condition:
        filesize < 5MB and
        any of ($cfg_*_xor2e)
}


rule CobaltStrike_Beacon_Config_Decoded
{
    meta:
        description = "Decoded CS beacon config — cleartext setting IDs in memory dumps or decrypted samples"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            Decoded config header: setting 0x0001 (BeaconType), type 0x0001 (short)
            followed by a valid beacon type value.
        */
        $decoded_header_http  = { 00 01 00 01 00 00 }   // BeaconType = HTTP
        $decoded_header_https = { 00 01 00 01 00 01 }   // BeaconType = HTTPS
        $decoded_header_smb   = { 00 01 00 01 00 02 }   // BeaconType = SMB
        $decoded_header_tcp   = { 00 01 00 01 00 04 }   // BeaconType = TCP
        $decoded_header_dns   = { 00 01 00 01 00 08 }   // BeaconType = DNS-TXT

        /*
            Setting 0x0003 = SleepTime, type 0x0002 (int).
            This always follows early in the config.
        */
        $sleep_setting = { 00 03 00 02 }

        /*
            Setting 0x0007 = PublicKey, type 0x0003 (data blob).
            The public key is 256 bytes; the length field is 00 01 00.
        */
        $pubkey_setting = { 00 07 00 03 01 00 }

        /*
            Setting 0x000A = Jitter, type 0x0001 (short).
        */
        $jitter_setting = { 00 0A 00 01 }

    condition:
        filesize < 50MB and    // memory dumps can be large
        any of ($decoded_header_*) and
        $sleep_setting and
        ($pubkey_setting or $jitter_setting)
}


rule CobaltStrike_Beacon_Config_Strings
{
    meta:
        description = "Plaintext strings commonly found in decoded beacon configs or memory"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "high"
        tlp         = "white"

    strings:
        /* Default malleable C2 profile indicators */
        $c2_submit  = "/submit.php" ascii
        $c2_visit   = "/visit.js" ascii
        $c2_pixel   = "/__utm.gif" ascii
        $c2_jquery  = "/jquery-3" ascii

        /* Common default metadata transform */
        $meta_cookie = "Cookie" ascii

        /* Spawnto default values — processes Cobalt Strike injects into */
        $spawn_x86 = "%windir%\\syswow64\\rundll32.exe" ascii nocase
        $spawn_x64 = "%windir%\\sysnative\\rundll32.exe" ascii nocase

        /* Watermark string prefix (see cs_watermarks.yar for full detection) */
        $watermark_prefix = { 00 25 00 01 }    // setting 0x0025 = Watermark

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*) and $meta_cookie) or
            (any of ($spawn_*) and any of ($c2_*)) or
            ($watermark_prefix and any of ($c2_*))
        )
}

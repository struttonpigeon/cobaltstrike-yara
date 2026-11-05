/*
    Cobalt Strike — Beacon Configuration Block Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/
                 https://github.com/Sentinel-One/CobaltStrikeParser

    Every Cobalt Strike beacon embeds a configuration block that tells it
    where to call home, how often to sleep, which named pipes to use, etc.

    CS 3.x stored the config XOR-encoded with key 0x69.
    CS 4.x XOR-encodes with key 0x2E.

    Each config entry follows the TLV layout:
        setting_id (2 bytes, big-endian)
        data_type  (2 bytes): 0x0001 = short, 0x0002 = int, 0x0003 = blob
        length     (2 bytes): byte length of the value field
        value      (variable)

    These rules detect both the encoded and decoded forms.
*/

rule CobaltStrike_Beacon_Config_XOR69
{
    meta:
        description = "CS beacon config XOR-encoded with key 0x69 (CS 3.x default)"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://github.com/Sentinel-One/CobaltStrikeParser"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            BeaconType (setting 0x0001, type short, length 0x0002):
            Decoded:  00 01 00 01 00 02 XX XX
            XOR 0x69: 69 68 69 68 69 6B YY YY

            BeaconType values: 0=HTTP, 8=HTTPS
        */
        $cfg_http_xor69  = { 69 68 69 68 69 6B 69 69 }   // HTTP  (0x0000)
        $cfg_https_xor69 = { 69 68 69 68 69 6B 69 61 }   // HTTPS (0x0008)

        /*
            Port (setting 0x0002, type short, length 0x0002):
            Decoded:  00 02 00 01 00 02 XX XX
            XOR 0x69: 69 6B 69 68 69 6B YY YY
        */
        $port_80_xor69  = { 69 6B 69 68 69 6B 69 39 }    // port 80  (0x0050)
        $port_443_xor69 = { 69 6B 69 68 69 6B 68 D2 }    // port 443 (0x01BB)

    condition:
        filesize < 5MB and
        any of ($cfg_*) and
        any of ($port_*)
}


rule CobaltStrike_Beacon_Config_XOR2E
{
    meta:
        description = "CS beacon config XOR-encoded with key 0x2E (CS 4.x default)"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            BeaconType (setting 0x0001, type short, length 0x0002):
            Decoded:  00 01 00 01 00 02 XX XX
            XOR 0x2E: 2E 2F 2E 2F 2E 2C YY YY

            NOTE: The 6-byte prefix 2E 2F 2E 2F 2E 2C is no longer the
            FP-prone "././.." (ASCII 2E 2F 2E 2F 2E 2E) because the
            length field byte (0x02 XOR 0x2E = 0x2C) breaks the pattern.
        */
        $cfg_http_xor2e  = { 2E 2F 2E 2F 2E 2C 2E 2E }   // HTTP  (0x0000)
        $cfg_https_xor2e = { 2E 2F 2E 2F 2E 2C 2E 26 }   // HTTPS (0x0008)

        /*
            Port (setting 0x0002, type short, length 0x0002):
            Decoded:  00 02 00 01 00 02 XX XX
            XOR 0x2E: 2E 2C 2E 2F 2E 2C YY YY
        */
        $port_80_xor2e  = { 2E 2C 2E 2F 2E 2C 2E 7E }    // port 80  (0x0050)
        $port_443_xor2e = { 2E 2C 2E 2F 2E 2C 2F 95 }    // port 443 (0x01BB)

    condition:
        filesize < 5MB and
        any of ($cfg_*) and
        any of ($port_*)
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
            BeaconType (setting 0x0001, type short 0x0001, length 0x0002):
            Full TLV header: 00 01 00 01 00 02
            Then the 2-byte value.

            CobaltStrikeParser type mapping:
              0x0000 = HTTP
              0x0002 = SMB
              0x0008 = HTTPS
        */
        $decoded_header_http  = { 00 01 00 01 00 02 00 00 }   // BeaconType = HTTP
        $decoded_header_smb   = { 00 01 00 01 00 02 00 02 }   // BeaconType = SMB
        $decoded_header_https = { 00 01 00 01 00 02 00 08 }   // BeaconType = HTTPS

        /*
            SleepTime (setting 0x0003, type int 0x0002, length 0x0004):
        */
        $sleep_setting = { 00 03 00 02 00 04 }

        /*
            PublicKey (setting 0x0007, type blob 0x0003, length 0x0100 = 256 bytes):
        */
        $pubkey_setting = { 00 07 00 03 01 00 }

        /*
            Jitter (setting 0x0005, type short 0x0001, length 0x0002):
        */
        $jitter_setting = { 00 05 00 01 00 02 }

    condition:
        filesize < 50MB and    // memory dumps can be large
        any of ($decoded_header_*) and
        $sleep_setting and
        ($pubkey_setting or $jitter_setting)
}


rule CobaltStrike_Beacon_Config_Strings
{
    meta:
        description = "Plaintext strings commonly found in decoded beacon configs or memory — supporting evidence, not standalone"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        severity    = "medium"
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

        /* Watermark setting header with length (setting 0x0025, type int 0x0002, length 0x0004) */
        $watermark_prefix = { 00 25 00 02 00 04 }

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*) and $meta_cookie) or
            (any of ($spawn_*) and any of ($c2_*)) or
            ($watermark_prefix and 2 of ($c2_*))
        )
}

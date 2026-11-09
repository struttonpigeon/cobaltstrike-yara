/*
    Cobalt Strike — Sleep Mask Kit Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Modified:    2026-11-10
    Reference:   https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures
                 https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/

    Cobalt Strike's sleep mask feature obfuscates the beacon in memory
    while it sleeps.  Before calling Sleep(), the beacon encrypts its own
    image, then decrypts on wake.  Some builds use a simple XOR loop;
    others use RC4 via SystemFunction032.

    CAVEAT: The byte patterns in these rules (XOR loops, stack frames,
    protection constants near indirect calls) are common compiler output and appear
    in many legitimate binaries.  These rules should be used as supporting
    evidence alongside other CS-specific detections (config blocks,
    named pipes, reflective loader), not as standalone alerts. API names
    do not establish that these code bytes call those APIs. Exporting
    modules can match too; no filename, signer or exporter is excluded.
    There is no whole-input size cap; these rules also scan large dumps.
*/

rule CobaltStrike_SleepMask_XOR_Stub : hunt
{
    meta:
        description = "Local same-architecture frame and XOR-loop bytes with a Sleep string — generic hunt evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            Supported x86 XOR forms use DL or BL and a simple base register
            without a SIB or displacement. Up to four intervening bytes
            precede two single-byte INC/DEC opcodes and a short JNZ.
        */
        $frame_loop_x86 = {
            55 89 E5 83 EC ?? 53 56 57
            [0-503]
            30 (10|11|12|13|16|17|18|19|1A|1B|1E|1F) [0-4] 4? 4? 75 ??
        }

        /*
            Supported x64 XOR forms also use DL or BL. REX.B (41) extends
            the memory base register. FF /0 is INC; FF /1 is DEC.
        */
        $frame_loop_x64 = {
            48 89 5C 24 ?? 48 89 6C 24 ??
            [0-502]
            41 30 (10|11|12|13|16|17|18|19|1A|1B|1E|1F)
            48 FF (C0|C1|C2|C3|C4|C5|C6|C7)
            48 FF (C8|C9|CA|CB|CC|CD|CE|CF) 75 ??
        }

        $sleep_str = "Sleep" ascii fullword

    condition:
        $sleep_str and any of ($frame_loop_*)
}


rule CobaltStrike_SleepMask_VirtualProtect : hunt
{
    meta:
        description = "Ordered protection-constant setup bytes near indirect calls, plus VirtualProtect and Sleep strings — generic hunt evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/"
        severity    = "medium"
        tlp         = "white"

    strings:
        $vp_str   = "VirtualProtect" ascii
        $sleep_fn = "Sleep" ascii fullword

        /*
            x86: PUSH imm8 within eight bytes of an indirect CALL.
            Compound pattern: RW setup/call then RWX setup/call within 512 bytes.
        */
        $protection_pair_x86 = {
            6A 04 [0-8] FF 15 ?? ?? ?? ??
            [0-512]
            6A 40 [0-8] FF 15 ?? ?? ?? ??
        }

        /*
            x64: MOV R8D-R15D, imm32 within 24 bytes of an indirect call.
            Wider register range covers compiler variation in register allocation.
        */
        $protection_pair_x64 = {
            41 (B8|B9|BA|BB|BC|BD|BE|BF) 04 00 00 00 [0-24] FF 15 ?? ?? ?? ??
            [0-512]
            41 (B8|B9|BA|BB|BC|BD|BE|BF) 40 00 00 00 [0-24] FF 15 ?? ?? ?? ??
        }

    condition:
        $vp_str and $sleep_fn and any of ($protection_pair_*)
}


rule CobaltStrike_SleepMask_RC4_SystemFunction032 : hunt
{
    meta:
        description = "SystemFunction032, SystemFunction036 and Sleep strings — generic crypto pattern, use as supporting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            SystemFunction032 is an undocumented Windows API that performs
            RC4 encryption. Advapi32.dll and cryptsp.dll export this function
            and can match these strings. This rule intentionally does not exclude
            exporters: it is a hunt lead, including in dumps of those modules.
        */
        $sf032_name = "SystemFunction032" ascii
        $sf036_name = "SystemFunction036" ascii
        $sleep_fn   = "Sleep" ascii fullword

    condition:
        $sf032_name and $sleep_fn and $sf036_name
}

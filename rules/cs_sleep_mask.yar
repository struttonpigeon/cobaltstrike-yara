import "pe"

/*
    Cobalt Strike — Sleep Mask Kit Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Modified:    2026-11-10
    Reference:   https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures
                 https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/

    Cobalt Strike's sleep mask feature obfuscates the beacon in memory
    while it sleeps.  Before calling Sleep(), the beacon encrypts its own
    image, then decrypts on wake.  The default sleep mask is a simple
    XOR loop.  RC4 via SystemFunction032 is mainly seen in community
    sleep-obfuscation techniques (e.g. Ekko-style timers) and custom
    Sleep Mask Kit builds, not in the default mask.

    MEASURED NOISE (2026-11-10, 13,546 benign files from System32,
    SysWOW64, Microsoft.NET and PowerShell 7 on Windows 11):
      SleepMask_VirtualProtect ........ 156 files with a 512-byte gap;
                                        see README for the 200-byte count
      SleepMask_RC4_SystemFunction032 .   8 files before exporter exclusion
    "Sleep" and "VirtualProtect" are imported by most Windows PEs, so the
    string checks below barely narrow the byte patterns.

    CAVEAT: The byte patterns in these rules (XOR loops, stack frames,
    protection constants near indirect calls) are common compiler output and appear
    in many legitimate binaries.  These rules should be used as supporting
    evidence alongside other CS-specific detections (config blocks,
    named pipes, reflective loader), not as standalone alerts. API names
    do not establish that these code bytes call those APIs. Only the RC4
    rule excludes PE files that export SystemFunction032; no filename or
    signer is excluded anywhere.
    There is no whole-input size cap; these rules also scan large dumps.
*/

rule CobaltStrike_SleepMask_XOR_Stub : hunt
{
    /*
        EXPERIMENTAL. No observed true positive: two decoded CS 4.2 public
        test stages (dissect.cobaltstrike "c2test_beacon" and
        "punycode_beacon") contain Elastic's published sleep-mask
        signature, yet this rule does not match them. Treat the pattern
        as an unvalidated heuristic until it is tied to a sample hash,
        offset, architecture and version.
    */
    meta:
        description = "EXPERIMENTAL: local frame and XOR-loop bytes with a Sleep string — unvalidated generic heuristic, not a CS sleep-mask signature"
        status      = "experimental"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "low"
        tlp         = "white"

    strings:
        /*
            Supported x86 XOR forms use DL or BL and a simple base register
            without a SIB or displacement. Up to four intervening bytes
            precede two single-byte INC/DEC opcodes and a short JNZ.
        */
        $frame_loop_x86 = {
            55 89 E5 83 EC ?? 53 56 57
            [0-255]
            30 (10|11|12|13|16|17|18|19|1A|1B|1E|1F) [0-4] 4? 4? 75 ??
        }

        /*
            Supported x64 XOR forms also use DL or BL. REX.B (41) extends
            the memory base register. FF /0 is INC; FF /1 is DEC.
        */
        $frame_loop_x64 = {
            48 89 5C 24 ?? 48 89 6C 24 ??
            [0-255]
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
        description = "Ordered protection-constant setup bytes near indirect calls, plus VirtualProtect and Sleep strings — very noisy generic hunt evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/"
        severity    = "low"
        tlp         = "white"

    strings:
        /* Known benign matches: 110 of 13,546 benign Windows files with
           the 200-byte gap (156 with the old 512-byte gap), e.g.
           combase.dll, lsasrv.dll, urlmon.dll, dbghelp.dll.
           Never alert on this rule alone; corroborate with config or
           stager evidence before escalating. */
        $vp_str   = "VirtualProtect" ascii
        $sleep_fn = "Sleep" ascii fullword

        /*
            x86: PUSH imm8 within eight bytes of an indirect CALL.
            Compound pattern: RW setup/call then RWX or RX restoration within 200 bytes.
            0x40 = PAGE_EXECUTE_READWRITE, 0x20 = PAGE_EXECUTE_READ (userwx=false, CS 4.10+).

            The middle gap must stay <= 200. Larger jumps split the pattern
            into chained pieces; with 512, YARA-X 1.23 took ~4.6 s per MiB
            of repeated setup/call fragments (vs ~0.04 s at 200). 200 also
            cut benign matches. Re-validate on real decoded stages after
            any change here.
        */
        $protection_pair_x86 = {
            6A 04 [0-8] FF 15 ?? ?? ?? ??
            [0-200]
            6A (20|40) [0-8] FF 15 ?? ?? ?? ??
        }

        /*
            x64: MOV R8D-R15D, imm32 within 24 bytes of an indirect call.
            Wider register range covers compiler variation in register allocation.
            0x40 = PAGE_EXECUTE_READWRITE, 0x20 = PAGE_EXECUTE_READ (userwx=false, CS 4.10+).
        */
        $protection_pair_x64 = {
            41 (B8|B9|BA|BB|BC|BD|BE|BF) 04 00 00 00 [0-24] FF 15 ?? ?? ?? ??
            [0-200]
            41 (B8|B9|BA|BB|BC|BD|BE|BF) (20|40) 00 00 00 [0-24] FF 15 ?? ?? ?? ??
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
            RC4 encryption. advapi32.dll, cryptsp.dll and others export or
            forward it. PE inputs that export SystemFunction032 themselves
            are excluded; non-PE inputs (raw memory, dumps) are still
            scanned, so a full process dump that contains advapi32 can
            still match.
        */
        $sf032_name = "SystemFunction032" ascii
        $sf036_name = "SystemFunction036" ascii
        $sleep_fn   = "Sleep" ascii fullword

    condition:
        $sf032_name and $sleep_fn and $sf036_name and
        /* pe.exports() is undefined on non-PE input, and "not undefined"
           is false, so guard with pe.is_pe to keep raw dumps in scope. */
        (not pe.is_pe or not pe.exports("SystemFunction032"))
}

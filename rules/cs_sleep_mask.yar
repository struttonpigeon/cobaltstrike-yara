/*
    Cobalt Strike — Sleep Mask Kit Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures
                 https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/

    Cobalt Strike's sleep mask feature obfuscates the beacon in memory
    while it sleeps.  Before calling Sleep(), the beacon encrypts its own
    image, then decrypts on wake.  Some builds use a simple XOR loop;
    others use RC4 via SystemFunction032.

    CAVEAT: The byte patterns in these rules (XOR loops, stack frames,
    VirtualProtect call sequences) are common compiler output and appear
    in many legitimate binaries.  These rules should be used as supporting
    evidence alongside other CS-specific detections (config blocks,
    named pipes, reflective loader), not as standalone alerts.
*/

rule CobaltStrike_SleepMask_XOR_Stub
{
    meta:
        description = "XOR obfuscation loop with Sleep — generic patterns shared by many tools, use as supporting evidence only"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            XOR loop body — byte-by-byte XOR with a key.
            30 1?              XOR BYTE PTR [reg], reg   ; XOR one byte
            4?                 INC/DEC
            4?                 INC/DEC
            75 ??              JNZ loop
        */
        $xor_loop_x86 = { 30 1? [0-4] 4? 4? 75 }

        /*
            x64 variant of the XOR loop:
            41 30 1?           XOR BYTE PTR [R??], r8b-ish
            48 FF C?           INC R??
            48 FF C?           DEC R??
            75 ??              JNZ loop
        */
        $xor_loop_x64 = { 41 30 [1-2] 48 FF C? 48 FF C? 75 }

        /*
            Function prologue patterns seen in default sleep mask stubs.
            NOTE: These are standard MSVC prologues that appear in many
            legitimate binaries; they add value only in combination with
            the XOR loop and Sleep string above.
        */
        $stack_frame_x86 = { 55 89 E5 83 EC ?? 53 56 57 }   // PUSH EBP; MOV EBP,ESP; SUB ESP,??; PUSH EBX,ESI,EDI
        $stack_frame_x64 = { 48 89 5C 24 ?? 48 89 6C 24 }   // MOV [RSP+?],RBX; MOV [RSP+?],RBP

        /*
            Sleep() call — the mask function calls kernel32!Sleep after
            encrypting the beacon.  Common pattern to look for:
            FF 15 ?? ?? ?? ??   CALL [Sleep_IAT_entry]
            ... or resolved dynamically via GetProcAddress("Sleep")
        */
        $sleep_str = "Sleep" ascii fullword

    condition:
        filesize < 10MB and
        any of ($xor_loop_*) and
        any of ($stack_frame_*) and
        $sleep_str
}


rule CobaltStrike_SleepMask_VirtualProtect
{
    meta:
        description = "Sleep mask with VirtualProtect memory protection flipping — generic patterns, use as supporting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            Some sleep mask variants call VirtualProtect twice:
              1. Before sleep: change beacon memory from RWX to RW (0x04)
              2. After sleep:  change back from RW to RWX (0x40)
        */
        $vp_str   = "VirtualProtect" ascii
        $sleep_fn = "Sleep" ascii fullword

        /*
            x86: PUSH imm8 near an indirect CALL [IAT]:
              6A 04  PUSH 4 (PAGE_READWRITE)
              6A 40  PUSH 0x40 (PAGE_EXECUTE_READWRITE)
        */
        $page_rw_x86  = { 6A 04 [0-8] FF 15 }
        $page_rwx_x86 = { 6A 40 [0-8] FF 15 }

        /*
            x64: MOV R8D-R15D, imm32.  41 B8..BF are the 32-bit register
            MOV opcodes; 41 B0..B7 are 8-bit MOVs (excluded).
              41 B? 04 00 00 00  MOV R?D, 4   (PAGE_READWRITE)
              41 B? 40 00 00 00  MOV R?D, 40h (PAGE_EXECUTE_READWRITE)
        */
        $page_rw_x64  = { 41 (B8|B9|BA|BB|BC|BD|BE|BF) 04 00 00 00 }
        $page_rwx_x64 = { 41 (B8|B9|BA|BB|BC|BD|BE|BF) 40 00 00 00 }

    condition:
        filesize < 10MB and
        $vp_str and $sleep_fn and
        (
            ($page_rw_x86 and $page_rwx_x86) or
            ($page_rw_x64 and $page_rwx_x64)
        )
}


rule CobaltStrike_SleepMask_RC4_SystemFunction032
{
    meta:
        description = "SystemFunction032 (RC4) + Sleep import in a non-system binary — generic crypto pattern, use as supporting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "medium"
        tlp         = "white"

    strings:
        /*
            SystemFunction032 is an undocumented Windows API that performs
            RC4 encryption.  Some C2 frameworks use it in place of a custom
            XOR loop for a smaller code footprint.
            NOTE: advapi32.dll and cryptsp.dll export this function and
            will match the string alone.  The Sleep requirement excludes
            most system DLLs.  For PE files, add a pe.exports() exclusion.
        */
        $sf032_name = "SystemFunction032" ascii
        $sf036_name = "SystemFunction036" ascii   // RtlGenRandom — used for key generation
        $sleep_fn   = "Sleep" ascii fullword

    condition:
        filesize < 10MB and
        $sf032_name and $sleep_fn and
        $sf036_name
}

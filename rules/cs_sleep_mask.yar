/*
    Cobalt Strike — Sleep Mask Kit Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures
                 https://www.sentinelone.com/labs/a-]deep-dive-into-cobalt-strike-malleable-c2/

    Starting with Cobalt Strike 4.1, the Sleep Mask kit was introduced to
    obfuscate the beacon in memory while it sleeps.  Before calling Sleep(),
    the beacon XOR-encrypts (or RC4-encrypts in 4.7+) its own image in
    memory, then decrypts it on wake.

    This defeats static memory scanners that look for beacon strings during
    the sleep interval.  However, the sleep mask code itself has distinctive
    patterns:

      1. The mask/unmask stub runs before and after Sleep() — its prologue
         is detectable.
      2. The XOR key derivation and loop have characteristic byte patterns.
      3. In CS 4.7+, the sleep mask can use the "sleepmask-vs" (virtual
         memory protect) variant, which calls VirtualProtect to flip
         RWX -> RW before sleeping and back on wake.
*/

rule CobaltStrike_SleepMask_XOR_Stub
{
    meta:
        description = "Cobalt Strike sleep mask XOR routine — the in-memory obfuscation loop"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            The default sleep mask (CS 4.1 – 4.6) XOR loop for x86.
            It iterates over the beacon image byte-by-byte, XORing with
            a 13-byte key (derived from the beacon config).

            Typical x86 assembly:
            8B 44 24 04        MOV EAX, [ESP+4]        ; pointer to data
            8B 4C 24 08        MOV ECX, [ESP+8]        ; data length
            8B 54 24 0C        MOV EDX, [ESP+0Ch]      ; pointer to key
            ...
            30 10              XOR BYTE PTR [EAX], DL   ; XOR one byte
            40                 INC EAX
            49                 DEC ECX
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
            The mask function has a predictable stack frame:
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
        description = "CS 4.7+ sleep mask with VirtualProtect — flips memory protections during sleep"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.sentinelone.com/labs/a-deep-dive-into-cobalt-strike-malleable-c2/"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            The "sleepmask-vs" variant calls VirtualProtect twice:
              1. Before sleep: change beacon memory from RWX to RW (0x04)
              2. After sleep:  change back from RW to RWX (0x40)

            The constants PAGE_READWRITE (0x04) and
            PAGE_EXECUTE_READWRITE (0x40) appear near VirtualProtect calls.
        */
        $vp_str   = "VirtualProtect" ascii
        $sleep_fn = "Sleep" ascii fullword

        /*
            Push 0x04 (PAGE_READWRITE) before VirtualProtect:
            6A 04           PUSH 4
            or
            41 B? 04 00 00 00  MOV R?D, 4   (x64)
        */
        $page_rw_x86  = { 6A 04 }
        $page_rw_x64  = { 41 B? 04 00 00 00 }

        /*
            Push 0x40 (PAGE_EXECUTE_READWRITE) after waking:
            6A 40           PUSH 40h
        */
        $page_rwx = { 6A 40 }

        /*
            CS 4.7+ sleep mask uses SystemFunction032 (RC4) from advapi32
            as an alternative to the XOR loop:
        */
        $rc4_fn   = "SystemFunction032" ascii
        $advapi   = "advapi32" ascii nocase

    condition:
        filesize < 10MB and
        $vp_str and $sleep_fn and
        (
            ($page_rw_x86 and $page_rwx) or
            ($page_rw_x64 and $page_rwx) or
            ($rc4_fn and $advapi)
        )
}


rule CobaltStrike_SleepMask_RC4_SystemFunction032
{
    meta:
        description = "CS 4.7+ sleep mask using ntdll/advapi32 SystemFunction032 for RC4 obfuscation"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            SystemFunction032 is an undocumented Windows API that performs
            RC4 encryption.  CS 4.7+ uses it instead of a custom XOR loop
            because it leaves a smaller and less distinctive code footprint.

            The function is imported by ordinal or name from advapi32.dll:
        */
        $sf032_name = "SystemFunction032" ascii
        $sf036_name = "SystemFunction036" ascii   // RtlGenRandom — used for key generation

        /*
            USTRING structure setup — SystemFunction032 takes two USTRING
            params (length, maxlength, buffer).  The struct setup pattern:
        */
        $ustring_setup = { 89 ?? 24 ?? 89 ?? 24 ?? 89 ?? 24 ?? }

        /*
            The beacon's image base and size are passed to the RC4 function.
            Typical pattern: loading the DOS header address:
        */
        $dos_header = { 48 8D ?? ?? ?? ?? ?? 48 89 }    // LEA reg, [rip+??]; MOV

    condition:
        filesize < 10MB and
        $sf032_name and
        ($sf036_name or $ustring_setup or $dos_header)
}

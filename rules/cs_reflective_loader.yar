/*
    Cobalt Strike — Reflective DLL Loader Detection
    Author:      struttonpigeon
    Date:        2026-11-05
    Reference:   https://github.com/stephenfewer/ReflectiveDLLInjection
                 https://www.mandiant.com/resources/defining-cobalt-strike-components

    Cobalt Strike beacons are position-independent DLLs injected via
    reflective loading (Stephen Fewer's technique, modified by Raphael Mudge).
    The reflective loader parses its own PE headers in-memory, resolves
    imports, applies relocations, and calls DllMain — all without touching
    the Windows loader.

    Two detection angles:
      1. The reflective loader stub itself (exported function + PE-parsing code).
      2. The "raw" beacon DLL characteristics (unusual section layout, no
         legitimate imports, specific PE header values).
*/

rule CobaltStrike_ReflectiveLoader_Export
{
    meta:
        description = "Detects the ReflectiveLoader export name in a PE — the entry point for reflective injection"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://github.com/stephenfewer/ReflectiveDLLInjection"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            The default export name.  Operators can rename it with the
            Artifact Kit, but many leave it as-is.  The wide variant
            catches UTF-16LE strings in some packers.
        */
        $export_ascii = "ReflectiveLoader" ascii fullword
        $export_wide  = "ReflectiveLoader" wide fullword

    condition:
        uint16(0) == 0x5A4D and    // MZ header
        filesize < 5MB and
        any of ($export_*)
}


rule CobaltStrike_ReflectiveLoader_Code
{
    meta:
        description = "Reflective loader PE-parsing code patterns — header walking and relocation logic"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://www.mandiant.com/resources/defining-cobalt-strike-components"
        severity    = "critical"
        tlp         = "white"

    strings:
        /*
            The reflective loader walks backwards from its own address to
            find the MZ header.  It checks:
              - WORD == 'MZ'  (0x5A4D)
              - then reads e_lfanew to find 'PE\0\0' (0x00004550)

            Typical x86 code:
            66 81 3B 4D 5A      CMP WORD PTR [EBX], 0x5A4D    ; 'MZ'
        */
        $mz_check = { 66 81 3? 4D 5A }

        /*
            After finding the MZ header the loader validates the PE sig:
            81 3? 50 45 00 00   CMP DWORD PTR [reg], 0x00004550  ; 'PE\0\0'
        */
        $pe_sig_check = { 81 3? 50 45 00 00 }

        /*
            Section iteration — the loader walks IMAGE_SECTION_HEADER entries
            to copy sections into the new allocation.  A common pattern is
            adding sizeof(IMAGE_SECTION_HEADER) == 0x28 (40 bytes) in a loop:
            83 C? 28            ADD reg, 28h
        */
        $section_iter = { 83 C? 28 }

        /*
            VirtualAlloc call setup — the loader allocates RWX memory for the
            beacon image.  The protection constant PAGE_EXECUTE_READWRITE = 0x40:
            6A 40               PUSH 40h
            68 00 30 00 00      PUSH 3000h    ; MEM_COMMIT | MEM_RESERVE
        */
        $valloc_rwx = { 6A 40 68 00 30 00 00 }

    condition:
        (
            uint16(0) == 0x5A4D or   // PE file
            uint8(0) == 0xFC         // raw shellcode
        ) and
        filesize < 5MB and
        $mz_check and $pe_sig_check and $section_iter and $valloc_rwx
}


rule CobaltStrike_Beacon_DLL_Characteristics
{
    meta:
        description = "Cobalt Strike beacon DLL — characteristic PE header values and minimal imports"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        reference   = "https://blog.didierstevens.com/2021/11/12/cobalt-strike-understanding-payloads/"
        severity    = "high"
        tlp         = "white"

    strings:
        /*
            Beacon DLLs often contain the string ".cobaltstrike" or
            "beacon" in section names, resource data, or config blocks.
            Operators can strip these, but default builds keep them.
        */
        $cs_str1 = ".cobaltstrike" ascii nocase
        $cs_str2 = "beacon.dll" ascii nocase
        $cs_str3 = "beacon.x64.dll" ascii nocase
        $cs_str4 = "beacon.x86.dll" ascii nocase

        /*
            Default mutex pattern — some CS versions create a mutex
            with this naming convention:
        */
        $mutex = "MSCTF.Asm." ascii

        /*
            The DLL entry point often just calls a single function and
            returns TRUE.  This pattern catches the boilerplate:
            B8 01 00 00 00      MOV EAX, 1
            C2 0C 00            RET 0Ch    ; stdcall DllMain(3 args)
        */
        $dllmain_ret = { B8 01 00 00 00 C2 0C 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($cs_str*) or
            ($mutex and $dllmain_ret)
        )
}

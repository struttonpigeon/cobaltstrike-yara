import "pe"

/*
    Reflective-loader and DLL hunting indicators
    Author: struttonpigeon
    Date: 2026-11-05
    Modified: 2026-11-10

    Reflective loading and these byte/string patterns are shared by many
    tools. A match does not establish Cobalt Strike or malicious intent.
    These file-oriented rules retain a strict input limit below 5 MiB.
    They do not reconstruct embedded PEs from a raw process dump.
*/

private rule IsPE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule CobaltStrike_ReflectiveLoader_Export : hunt
{
    meta:
        description = "Parsed ReflectiveLoader export; shared with Metasploit and other RDI-based tools"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/stephenfewer/ReflectiveDLLInjection"
        shared_with = "Metasploit and other RDI-based tools"
        severity    = "medium"
        tlp         = "white"

    condition:
        /* x86 builds usually export the stdcall-decorated name
           "_ReflectiveLoader@4"; pe.exports() with a plain string is an
           exact-name match, so a regex is needed to cover both. */
        filesize < 5MB and pe.is_pe and
        pe.exports(/^_?ReflectiveLoader(@[0-9]+)?$/)
}


rule CobaltStrike_ReflectiveLoader_Name : hunt
{
    meta:
        description = "ReflectiveLoader text in a PE-like file without a verified named export"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://github.com/stephenfewer/ReflectiveDLLInjection"
        shared_with = "Metasploit and other RDI-based tools; arbitrary embedded text"
        severity    = "medium"
        tlp         = "white"

    strings:
        $name = "ReflectiveLoader" ascii wide fullword

    condition:
        IsPE and filesize < 5MB and $name and
        not CobaltStrike_ReflectiveLoader_Export
}


rule CobaltStrike_ReflectiveLoader_Code : hunt
{
    meta:
        description = "Generic x86 PE-signature comparison and allocation-constant bytes; supporting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://www.mandiant.com/resources/defining-cobalt-strike-components"
        shared_with = "Packers, PE injectors and other native code"
        severity    = "medium"
        tlp         = "white"

    strings:
        /* CMP group /7 with mod=00, simple base-register memory operands:
           [EAX], [ECX], [EDX], [EBX], [ESI], [EDI]. Exclude 3C (SIB) and
           3D (disp32), and all /6 XOR forms. */
        $mz_check = { 66 81 (38|39|3A|3B|3E|3F) 4D 5A }

        $pe_sig_check = { 81 (38|39|3A|3B|3E|3F) 50 45 00 00 }

        /* ADD group /0, register operand followed by a short conditional
           jump (loop back). Adding 40 bytes is the section-header stride. */
        $section_iter = { 83 (C0|C1|C2|C3|C4|C5|C6|C7) 28 [0-12] 75 ?? }

        /* PUSH 0x40; PUSH 0x3000: constants compatible with an allocation setup. */
        $valloc_rwx = { 6A 40 68 00 30 00 00 }

    condition:
        (uint16(0) == 0x5A4D or uint8(0) == 0xFC) and
        filesize < 5MB and
        $mz_check and $pe_sig_check and $section_iter and $valloc_rwx
}


rule CobaltStrike_Beacon_DLL_Characteristics : hunt
{
    meta:
        description = "Parsed PE DLL (x86 or x64) whose export-directory name is a default beacon DLL name"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://blog.didierstevens.com/2021/11/12/cobalt-strike-understanding-payloads/"
        severity    = "medium"
        tlp         = "white"

    condition:
        /* pe.dll_name is the Name field of the parsed export directory,
           so this cannot be satisfied by the text appearing elsewhere in
           the file. A malleable profile's stage.name changes this value. */
        filesize < 5MB and
        pe.is_pe and
        (pe.characteristics & pe.DLL) != 0 and
        /* "matches" with /i rather than iequals, which needs a newer
           YARA 4.x release than the rest of this pack. */
        pe.dll_name matches /^beacon(\.x64)?\.dll$/i
}

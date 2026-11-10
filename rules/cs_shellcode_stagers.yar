/*
    Cobalt Strike / block_api-style shellcode hunting indicators
    Author: struttonpigeon
    Date: 2026-11-05
    Modified: 2026-11-10

    These byte layouts are shared with Metasploit and other block_api users.
    They do not establish Cobalt Strike attribution or malicious intent.

    The ordered sequence includes prologue, PEB-walk fragment and ROR-13.
    Each intervening gap is independently 0..128 bytes.

    x86: FC = CLD; E8 ?? 00 00 00 = CALL with small displacement.
    PEB variants clear EAX (MSF: 31 C0) or EDX (CS: 31 D2), then
    read FS:[reg+30h], Ldr, InMemoryOrderModuleList.
    C1 CF 0D = ROR EDI,13.

    x64: FC = CLD; 48 83 E4 F0 = AND RSP,-16; E8 has four displacement bytes.
    PEB reads GS:[RDX+60h], Ldr, InMemoryOrderModuleList.
    41 C1 C9 0D = ROR R9D,13.

    Raw variants anchor at offset zero. Embedded variants accept any
    complete sequence starting after zero.
*/

rule CobaltStrike_Shellcode_Stager_x86 : hunt
{
    meta:
        description = "Ordered x86 block_api-style bytes at offset zero; shared hunting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        shared_with = "Metasploit and other block_api users"
        severity    = "high"
        tlp         = "white"

    strings:
        $sequence = {
            FC E8 ?? 00 00 00
            [0-128]
            60 89 E5 (31 C0 64 8B 50 30 | 31 D2 64 8B 52 30)
            8B 52 0C 8B 52 14
            [0-128]
            C1 CF 0D
        }

    condition:
        $sequence at 0
}


rule CobaltStrike_Shellcode_Stager_x64 : hunt
{
    meta:
        description = "Ordered x64 block_api-style bytes at offset zero; shared hunting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        shared_with = "Metasploit and other block_api users"
        severity    = "high"
        tlp         = "white"

    strings:
        $sequence = {
            FC 48 83 E4 F0 E8 ?? ?? ?? ??
            [0-128]
            65 48 8B 52 60 48 8B 52 18 48 8B 52 20
            [0-128]
            41 C1 C9 0D
        }

    condition:
        $sequence at 0
}


rule CobaltStrike_Shellcode_Stager_x86_Embedded : hunt
{
    meta:
        description = "Ordered x86 block_api-style bytes at a nonzero offset; shared hunting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        shared_with = "Metasploit and other block_api users"
        severity    = "high"
        tlp         = "white"

    strings:
        $sequence = {
            FC E8 ?? 00 00 00
            [0-128]
            60 89 E5 (31 C0 64 8B 50 30 | 31 D2 64 8B 52 30)
            8B 52 0C 8B 52 14
            [0-128]
            C1 CF 0D
        }

    condition:
        /* Match offsets are reported in ascending order, so the last
           match is at a nonzero offset iff any match is. O(1), unlike a
           loop over every match (yara-x: potentially_slow_loop). */
        @sequence[#sequence] > 0
}


rule CobaltStrike_Shellcode_Stager_x64_Embedded : hunt
{
    meta:
        description = "Ordered x64 block_api-style bytes at a nonzero offset; shared hunting evidence"
        author      = "struttonpigeon"
        date        = "2026-11-05"
        modified    = "2026-11-10"
        reference   = "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/"
        shared_with = "Metasploit and other block_api users"
        severity    = "high"
        tlp         = "white"

    strings:
        $sequence = {
            FC 48 83 E4 F0 E8 ?? ?? ?? ??
            [0-128]
            65 48 8B 52 60 48 8B 52 18 48 8B 52 20
            [0-128]
            41 C1 C9 0D
        }

    condition:
        /* Match offsets are reported in ascending order, so the last
           match is at a nonzero offset iff any match is. O(1), unlike a
           loop over every match (yara-x: potentially_slow_loop). */
        @sequence[#sequence] > 0
}

/*
    CobaltStrike_Shellcode_Stager_Generic was removed on 2026-11-10.
    It required a plaintext "wininet" string, plaintext WinInet API names
    and one exact User-Agent, but default stagers resolve APIs by hash
    and their User-Agent varies, so it could essentially never match.
*/

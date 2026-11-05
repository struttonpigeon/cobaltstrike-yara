<div align="center">

# Cobalt Strike YARA Rule Pack

**22 detection rules for Cobalt Strike loaders, beacons, and post-exploitation artifacts**
IM DOING THIS BECAUSE MY INTERNAL RED TEAM IS GRIEFING ME

[![YARA](https://img.shields.io/badge/YARA-4.x-blue?style=flat-square)](https://virustotal.github.io/yara/)
[![Rules](https://img.shields.io/badge/rules-22-green?style=flat-square)](#rule-inventory)
[![CS Version](https://img.shields.io/badge/Cobalt%20Strike-3.x--4.x-red?style=flat-square)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](#license)

[Quick Start](#quick-start) | [Rule Inventory](#rule-inventory) | [Methodology](#methodology) | [Limitations](#limitations--evasion)

</div>

---

## What This Is

A curated set of YARA rules that detect **Cobalt Strike** artifacts across every stage of the attack chain — from initial shellcode stagers through in-memory beacon configurations. Each rule is heavily commented, explaining exactly which bytes are matched and why, making this useful both as a **detection toolset** and a **learning resource**.

These rules target **default and lightly customised** CS deployments (versions 3.x through 4.x), which still account for the majority of Cobalt Strike usage observed in the wild.

For those of you whose red team uses CS without obfuscation... this is for you.

## Quick Start

```bash
# Clone
git clone https://github.com/struttonpigeon/cobaltstrike-yara.git
cd cobaltstrike-yara

# Scan a suspect file
yara rules/cs_beacon_config.yar suspect.bin

# Scan recursively with all rules
yara -r rules/ /path/to/samples/

# Scan a memory dump
yara -r rules/ process_dump.dmp
```

## Rule Inventory

| File | Rules | Detection Surface |
|:-----|:-----:|:------------------|
| [`cs_shellcode_stagers.yar`](rules/cs_shellcode_stagers.yar) | 3 | x86/x64 stager prologues (`CLD`+`CALL`), PEB walk, ROR-13 API hashing, WinInet HTTP staging |
| [`cs_reflective_loader.yar`](rules/cs_reflective_loader.yar) | 3 | `ReflectiveLoader` export, PE-header parsing stub, beacon DLL characteristics |
| [`cs_beacon_config.yar`](rules/cs_beacon_config.yar) | 4 | XOR-encoded config blocks (keys `0x69`, `0x2E`), decoded setting IDs, default C2 URI strings |
| [`cs_named_pipes.yar`](rules/cs_named_pipes.yar) | 2 | Default SMB beacon and post-ex pipe names (`msagent_`, `MSSE-`, `postex_`), malleable C2 profile directives |
| [`cs_powershell_loaders.yar`](rules/cs_powershell_loaders.yar) | 3 | PowerShell download cradles, .NET `Assembly.Load` reflective execution, HTA/VBS delivery wrappers |
| [`cs_sleep_mask.yar`](rules/cs_sleep_mask.yar) | 3 | Sleep mask XOR loop, `VirtualProtect` memory protection flipping, RC4 via `SystemFunction032` |
| [`cs_watermarks.yar`](rules/cs_watermarks.yar) | 4 | Known cracked/leaked license watermarks (decoded + XOR-encoded), generic watermark field detection |

> Every rule includes a `severity` meta field: **critical** (near-certain CS), **high** (strong indicator), or **medium** (supporting evidence).

## Attack Chain Coverage

```
  DELIVERY                 EXECUTION                POST-EXPLOITATION
  ======================== ======================== ========================
  HTA / VBS wrapper        Shellcode stager         Beacon config block
  PowerShell cradle        Reflective DLL loader    Named pipe comms
  .NET Assembly.Load       PEB walk + API hashing   Sleep mask obfuscation
  Encoded commands         VirtualAlloc + RWX       Watermark / license ID
```

## Methodology

### Sample Sources

| Source | What It Provided |
|:-------|:-----------------|
| [MalwareBazaar](https://bazaar.abuse.ch/) | Tagged Cobalt Strike beacon and stager samples |
| [VirusTotal](https://www.virustotal.com/) | Community-tagged samples, behavioral reports |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Sandbox execution reports with CS indicators |
| [The DFIR Report](https://thedfirreport.com/) | Full intrusion case studies with IOC sets |
| [Elastic Security Labs](https://www.elastic.co/security-labs) | Memory signature research |
| [SentinelOne Labs](https://www.sentinelone.com/labs/) | CS internals deep dives |

### Analysis Toolchain

| Tool | Role |
|:-----|:-----|
| PE-bear / CFF Explorer | PE header inspection |
| x64dbg / IDA Pro | Shellcode and loader disassembly |
| CyberChef | XOR brute-force decoding |
| [CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser) | Automated config extraction |
| [1768.py](https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/) | Beacon config decoding |
| strings / FLOSS | Obfuscated string extraction |

### Pattern Extraction Process

1. **Disassemble** — identify byte sequences unique to Cobalt Strike, not shared with Metasploit, Sliver, or legitimate software.
2. **Cross-reference** — confirm stability across multiple versions and campaign samples.
3. **Compute XOR variants** — pre-compute encoded byte patterns for the two most common config XOR keys (`0x69` and `0x2E`).
4. **Validate** — test against non-CS samples (Metasploit, Sliver, Brute Ratel, clean PE files) to verify low false-positive rate.
5. **Layer conditions** — require multiple string matches per rule to prevent noise from partial byte collisions.

## Test Samples

[`samples/known_hashes.txt`](samples/known_hashes.txt) contains SHA-256 hashes of publicly documented samples with the expected rule matches for each. To validate:

```bash
# Download a sample from MalwareBazaar
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -d "query=get_file&sha256_hash=<HASH>" -o sample.zip

# Unzip (password: infected) in an isolated environment
unzip -P infected sample.zip

# Test
yara -r rules/ sample.bin
```

> **Handle all samples in an isolated analysis VM. Never execute on production systems.**

## Limitations & Evasion

These rules catch **default and lightly modified** deployments. Mature operators evade them with:

| Technique | Effect |
|:----------|:-------|
| **Malleable C2 profiles** | Custom URIs, headers, and pipe names replace all defaults |
| **Artifact Kit** | Recompiles loader with custom code, removing default byte patterns |
| **Sleep Mask Kit mods** | Custom encryption replaces XOR/RC4 |
| **UDRL** (User-Defined Reflective Loader) | Replaces the entire reflective loading mechanism |
| **Process injection diversity** | Avoids default fork-and-run |
| **Profile obfuscation** (e.g., SourcePoint) | Generates unique profiles per engagement |

### Recommended Complementary Defenses

- **ETW telemetry** — monitor `NtAllocateVirtualMemory`, `NtCreateThreadEx`, `RtlCreateUserThread`
- **Memory scanning** — [BeaconEye](https://github.com/CCob/BeaconEye), [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons)
- **Network signatures** — JA3/JA3S fingerprinting, HTTP profile anomaly detection
- **Behavioral rules** — Sigma rules for process injection, named pipe creation, PowerShell abuse

## Project Structure

```
cobaltstrike-yara/
├── README.md
├── rules/
│   ├── cs_shellcode_stagers.yar    # Shellcode stager prologues
│   ├── cs_reflective_loader.yar    # Reflective DLL injection
│   ├── cs_beacon_config.yar        # Encoded + decoded beacon configs
│   ├── cs_named_pipes.yar          # SMB beacon & post-ex pipes
│   ├── cs_powershell_loaders.yar   # PowerShell / .NET / HTA loaders
│   ├── cs_sleep_mask.yar           # Sleep mask obfuscation
│   └── cs_watermarks.yar           # Cracked license watermarks
└── samples/
    └── known_hashes.txt            # Public sample hashes for validation
```

## Contributing

Contributions welcome. To add a rule:

1. Fork this repo
2. Add your rule to the appropriate `.yar` file (or create a new one for a new detection surface)
3. Include `meta:` fields: `description`, `author`, `date`, `reference`, `severity`, `tlp`
4. Comment the byte patterns — explain **what** each sequence is in the disassembly
5. Test against at least one known CS sample and one non-CS sample
6. Open a PR with the sample hash(es) you validated against

## References

- [The DFIR Report — Cobalt Strike, a Defender's Guide (2021)](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/)
- [Elastic Security Labs — Detecting Cobalt Strike with Memory Signatures](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures)
- [SentinelOne — CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [Didier Stevens — Cobalt Strike Decoding](https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/)
- [Mandiant — Defining Cobalt Strike Components](https://www.mandiant.com/resources/defining-cobalt-strike-components)
- [Unit 42 — Cobalt Strike Malleable C2](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/)
- [Michael Koczwara — Cobalt Strike Watermark Analysis](https://michaelkoczwara.medium.com/cobalt-strike-watermark-analysis-bc0aecec28cd)
- [Stephen Fewer — Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)

## License

MIT License. These rules are released for defensive security research and incident response.

---

<div align="center">

**If this helped your detection engineering or incident response work, consider giving it a star.**

</div>

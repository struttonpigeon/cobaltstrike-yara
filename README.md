<div align="center">

# Cobalt Strike YARA Rule Pack

**26 detection rules + 1 private helper for Cobalt Strike loaders, beacons, and post-exploitation artifacts**

[![YARA](https://img.shields.io/badge/YARA-4.x%20%7C%20YARA--X-blue?style=flat-square)](https://virustotal.github.io/yara/)
[![Rules](https://img.shields.io/badge/rules-26+1-green?style=flat-square)](#rule-inventory)
[![CS Version](https://img.shields.io/badge/Cobalt%20Strike-4.x%20%28configs%204.2--4.12%20validated%29-red?style=flat-square)](#external-validation)
[![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](#license)
[![CI](https://github.com/struttonpigeon/cobaltstrike-yara/actions/workflows/yara-ci.yml/badge.svg)](https://github.com/struttonpigeon/cobaltstrike-yara/actions/workflows/yara-ci.yml)

[Quick Start](#quick-start) | [Supported Inputs](#supported-inputs) | [Rule Inventory](#rule-inventory) | [Methodology](#methodology) | [Testing](#testing) | [Known FPs](#known-false-positives) | [Limitations](#limitations--evasion)

</div>

---

## What This Is

This document was inspired by my wonderful internal red team who should really use the Artifact Kit more ;)

This is a curated set of YARA rules that detect **Cobalt Strike** artifacts across every stage of the attack chain. It covers initial shellcode stagers through serialized beacon configuration blocks (as found in decrypted beacon DLLs and in memory regions that still hold the raw block — not the parsed settings table a running beacon keeps on its heap). Each rule is heavily commented, explaining exactly which bytes are matched and why, making this useful both as a detection toolset and a learning resource.

These rules target default and lightly customised CS 4.x deployments. The config rules have been validated against decoded configs from eight public CS 4.2–4.12 test Beacons (see [External Validation](#external-validation)); no CS 3.x sample has been validated, and the other rule families have little or no real-sample evidence yet. Operators using Artifact Kit, UDRL, or Sleep Mask Kit modifications will evade many of these signatures — see [Limitations](#limitations--evasion) below.

For those of you whose red team uses CS without obfuscation... COUGH COUGH this is for you.

## Quick Start

> [!IMPORTANT]
> **Decode payload files before you scan them.** Cobalt Strike payloads are wrapped in an outer encoding layer that hides the Beacon config. Scanned as-is, a real Beacon will usually match **nothing**: in eight public test Beacons, **0 of 8** original files matched a `core` rule, and **8 of 8** matched once a parser had removed that layer. **No match on an original payload file does not mean it is clean.** Memory dumps and scripts can be scanned directly.

### 1. Install YARA and a Beacon parser

| Tool | Windows | Linux | macOS |
|:--|:--|:--|:--|
| YARA | Download `yara-*-win64.zip` from [YARA releases](https://github.com/VirusTotal/yara/releases) and use `yara64.exe` in place of `yara` below | `sudo apt install yara` | `brew install yara` |
| Beacon parser | `pip install dissect.cobaltstrike` | same | same |

[`dissect.cobaltstrike`](https://github.com/fox-it/dissect.cobaltstrike) (Fox-IT) provides the `beacon-dump` and `beacon-xordecode` commands used below.

### 2. Get the rules

```bash
git clone https://github.com/struttonpigeon/cobaltstrike-yara.git
cd cobaltstrike-yara
```

### 3. Scan — pick the path that matches what you have

**A. A suspected payload file (EXE, DLL, `.bin`): decode first, then scan**

```bash
# Quick answer: prints the Beacon config if the parser can find one.
# It handles the outer XOR layer and tries every config XOR key, including custom ones.
beacon-dump suspect.bin

# Remove the outer XOR layer, then scan the decoded payload
beacon-xordecode suspect.bin -o decoded.bin
yara -w -t core index.yar decoded.bin
```

If `beacon-dump` prints a config, you are almost certainly looking at a Beacon — the YARA scan then adds watermark and hunt context. If `beacon-xordecode` cannot decode the file, it may use a different transform or not be a Beacon payload: rely on `beacon-dump`, or scan the original file for the non-config rules (stagers, reflective loader, Artifact Kit pipe).

**B. A memory dump or a folder sweep: scan directly**

```bash
yara -w -t core index.yar process_dump.dmp
yara -w -r -t core index.yar /path/to/folder
```

A folder sweep finds decoded or in-memory artefacts, not wrapped payloads — send any suspicious executable it turns up through path A.

**C. Scripts (PowerShell, HTA, VBScript): scan directly**

```bash
yara -w -r index.yar /path/to/scripts
```

The script-loader rules are `hunt`-tagged and generic (they also match Empire, PowerSploit, etc.), so leave off `-t core` here.

> **Handle suspected payloads only in an isolated analysis VM.** Decoding and scanning are static — never execute the file.

### 4. Read the results

Each output line is `RuleName path/to/file`. No output means no rule matched.

| What matched | What to do |
|:--|:--|
| `core` rule | Treat as a likely Beacon config and investigate. |
| `hunt` rule with severity `critical` or `high` | Strong lead; look for corroborating evidence. |
| `hunt` rule with severity `medium` or `low` | Supporting evidence only — never alert on it alone (e.g. `SleepMask_VirtualProtect` matches 110 normal Windows files). |

Flags used above: `-w` hides four known "may slow down scanning" warnings, `-t core` reports only the three high-confidence config rules, and `-r` recurses into folders. Drop `-t core` to see every hunt rule.

### Other ways to run

```bash
# YARA-X (run from the repo root so index.yar includes resolve)
yr scan index.yar /path/to/target

# Compile once, then reuse
yarac index.yar compiled.yarc
yara -w -C -r compiled.yarc /path/to/folder

# One self-contained rule file, for tools that do not follow include lines
# (Velociraptor, Wazuh, osquery's yara table, THOR/Loki custom signatures)
cat rules/*.yar > cobaltstrike_all.yar
```

On Windows PowerShell, build the single file with `Get-Content rules\*.yar | Set-Content cobaltstrike_all.yar`.

## Supported Inputs

What you scan matters more than which rule file you load. In eight public test Beacons, **0 of 8 original payload files** matched a core rule, while **8 of 8 decoded configs** did: the config is hidden behind an outer payload encoding until a parser removes it.

| Input you scan | Rules that can fire | Notes |
|:--|:--|:--|
| Original payload / delivery file (stageless EXE or DLL, archived payload, raw `.bin`) | Shellcode stagers (raw shellcode), `ArtifactKit_Pipe_Format`, `ReflectiveLoader_*`, `Generic_*` scripts | Config and watermark rules usually **cannot** see through the outer payload encoding. "No match" here is not "clean". |
| Decoded Beacon stage (outer encoding removed) | Config `XOR69`/`XOR2E`, watermark rules, `ReflectiveLoader_*`, `Beacon_DLL_Characteristics`, sleep-mask hunts | Only the default config keys `0x69` and `0x2E` are matched in encoded form; custom keys (e.g. `0xCC`, `0xAF`) are not. |
| Extracted, decoded config block | `Beacon_Config_Decoded`, `Beacon_Config_Strings`, watermark rules | The most reliable input for the `core` rules. |
| Memory dump file | Config rules (while the raw block is still resident), `Named_Pipes_Default`, sleep-mask hunts | The parsed settings table a running Beacon builds on its heap is **not** matched. Whole-dump string co-occurrence can combine evidence from unrelated modules. |
| Live process (`yara index.yar <pid>`) | Rules without `filesize` or MZ checks | Untested. `filesize` is undefined for a PID, so `ReflectiveLoader_*`, `ArtifactKit_Pipe_Format` and the `Generic_*` loaders cannot fire. |

To get from an original payload to a decoded stage or config, use a maintained parser — [`dissect.cobaltstrike`](https://github.com/fox-it/dissect.cobaltstrike) (`beacon-dump`, `beacon-xordecode`; commands in [Quick Start](#quick-start)) or Didier Stevens' [`1768.py`](https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/) — then scan the decoded output. Payloads with additional transforms (for example the 4.12 base64/RC4 obfuscation layers) may need the parser's Python API rather than `beacon-xordecode`. Do this statically, in an isolated analysis environment.

## Rule Inventory

| File | Rules | Detection Surface |
|:-----|:-----:|:------------------|
| [`cs_shellcode_stagers.yar`](rules/cs_shellcode_stagers.yar) | 4 | Compound ordered sequences: prologue → PEB walk (MSF + CS variants) → ROR-13 API hashing for x86/x64 raw and embedded stagers |
| [`cs_reflective_loader.yar`](rules/cs_reflective_loader.yar) | 4+1 | `ReflectiveLoader` parsed export (plain and stdcall-decorated) and name-only variants, PE-header parsing stub, default beacon DLL export name (`pe.dll_name`), `IsPE` private helper |
| [`cs_beacon_config.yar`](rules/cs_beacon_config.yar) | 4 | Ordered 5-TLV prefix matching (settings 1–5) in decoded, XOR `0x69`, and XOR `0x2E` forms; default C2 URI and spawnto strings |
| [`cs_named_pipes.yar`](rules/cs_named_pipes.yar) | 3 | Artifact Kit pipe-name format string in PE files; default SMB beacon and post-ex pipe names (`msagent_`, `MSSE-`, `postex_`) mainly in decoded memory; malleable C2 profile directives |
| [`cs_powershell_loaders.yar`](rules/cs_powershell_loaders.yar) | 3 | Generic PowerShell/`.NET`/HTA script loaders (match CS + Empire, PowerSploit, Covenant, etc.); the `.NET` rule skips PE files, the PowerShell and HTA rules also scan PEs (a public 4.10 Beacon matched the PowerShell rule); HTA tag tolerates quote/attribute/spacing variation |
| [`cs_sleep_mask.yar`](rules/cs_sleep_mask.yar) | 3 | **Experimental** frame+XOR-loop heuristic (no observed true positive), ordered `VirtualProtect` protection pairs within 200 bytes (RW→RWX and RW→RX for CS 4.10+ `userwx=false`), `SystemFunction032` RC4 strings (community sleep-obfuscation style, not the default mask) — **noisy, supporting evidence only** |
| [`cs_watermarks.yar`](rules/cs_watermarks.yar) | 5 | Known cracked/leaked watermarks and watermark 0, each anchored to the config prefix, in decoded, XOR `0x69`, and XOR `0x2E` forms; prefix-anchored structural watermark field detection |

> Every rule is tagged **`core`** (config-block signatures with low expected FP rate, but see [Known False Positives](#known-false-positives) below) or **`hunt`** (threat-hunting leads that benefit from human triage or corroborating evidence). Each rule also includes a `severity` meta field: **critical** (known-bad indicators like cracked watermarks), **high** (strong structural signatures), **medium** (supporting evidence, use alongside other detections), or **low** (measurably noisy on benign software; never alert on these alone). Rules shared with Metasploit or generic toolkits are documented via the `shared_with` meta field.

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

### References Consulted

| Source | Relevance |
|:-------|:----------|
| [MalwareBazaar](https://bazaar.abuse.ch/) | Tagged Cobalt Strike beacon and stager samples |
| [VirusTotal](https://www.virustotal.com/) | Community-tagged samples, behavioral reports |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Sandbox execution reports with CS indicators |
| [The DFIR Report](https://thedfirreport.com/) | Full intrusion case studies with IOC sets |
| [Elastic Security Labs](https://www.elastic.co/security-labs) | Memory signature research |
| [SentinelOne Labs](https://www.sentinelone.com/labs/) | CS internals deep dives |
| [CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser) | Config field definitions and TLV layout |
| [1768.py](https://blog.didierstevens.com/2021/11/03/cobalt-strike-decoding/) | Beacon config decoding methodology |

> **Note:** Reference URLs were current as of 2026-11-05 and have not been re-checked since. Some may have moved or become unavailable.

### Pattern Extraction Process

1. **Disassemble** — identify byte sequences characteristic of Cobalt Strike. Some patterns (PEB walk, ROR-13 hashing) are shared with Metasploit's block\_api shellcode; `shared_with` metadata notes this where applicable.
2. **Cross-reference** — check stability using public reports and decoded configs. Real-sample evidence so far covers decoded configs from CS 4.2–4.12 only; see [External Validation](#external-validation).
3. **Compute XOR variants** — pre-compute encoded byte patterns for the two most common config XOR keys (`0x69` and `0x2E`), including the full TLV layout (setting ID + type + length + value).
4. **Layer conditions** — require multiple string matches per rule to prevent noise from partial byte collisions.

## Test Samples

[`samples/known_hashes.txt`](samples/known_hashes.txt) lists the SHA-256 hashes, provenance and per-representation results for the public test Beacons below, plus the format for contributing more. No sample files are stored in this repository. To validate a sample you have obtained from a public repository:

```bash
# Download a sample from MalwareBazaar
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -d "query=get_file&sha256_hash=<HASH>" -o sample.zip

# Unzip (password: infected) in an isolated environment
unzip -P infected sample.zip

# Test against all rules
yara index.yar sample.bin
```

> **Handle all samples in an isolated analysis VM. Never execute on production systems.**

### External Validation

An independent review at commit `84c3ccf` (2026-11-10) statically scanned eight public test Beacons from the [`fox-it/dissect.cobaltstrike`](https://github.com/fox-it/dissect.cobaltstrike/tree/fb1a38e779d2e4fd68c3d9b4a8d001c704e992bc/tests/beacons) test suite (parser-estimated CS 4.2, 4.3, 4.4, 4.10 and 4.12; x86 and x64). Nothing was executed.

| Representation | Result |
|:--|:--|
| Original payload files | 0/8 matched a `core` rule; 1/8 matched hunt rules only |
| Decoded stages, default key `0x2E` | `Beacon_Config_XOR2E` matched every fully decoded stage |
| Decoded stages, custom keys `0xCC` / `0xAF` | No config match (custom keys unsupported) |
| Extracted decoded configs | 8/8 matched `Beacon_Config_Decoded`; 8/8 matched `Watermark_Setting_Present` |

These results predate the 2026-11-10 rule changes (anchored watermark rules, 200-byte `VirtualProtect` gap, decorated-export support, `pe.dll_name`) and **should be re-run**. Hashes and exact matches are in [`samples/known_hashes.txt`](samples/known_hashes.txt).

## Testing

[`tests/run_tests.py`](tests/run_tests.py) compiles every rule file plus `index.yar`, then checks that each blob in `test_blobs/` produces **exactly** the rules listed in [`tests/expected.json`](tests/expected.json) (an empty list is a negative test). It also fails if a rule has neither a positive blob nor an entry in `pending_positive_fixtures`, so coverage gaps stay visible.

```bash
pip install yara-python && python tests/run_tests.py --engine libyara
pip install yara-x      && python tests/run_tests.py --engine yarax
```

[`.github/workflows/yara-ci.yml`](.github/workflows/yara-ci.yml) runs both engines on every push to `main` and on every pull request.

> **Current coverage:** only 4 of 26 rules have an in-repo positive fixture. The `core` config rules have **no** in-repo fixture yet (they do have [external validation](#external-validation)) — contributions of fixtures derived from public, hashed samples are the most valuable help this project can get.

libyara 4.5.4 reports "may slow down scanning" for `$section_iter` (`cs_reflective_loader.yar`) and for `$frame_loop_x86`, `$protection_pair_x86` and `$protection_pair_x64` (`cs_sleep_mask.yar`); YARA-X reports no warnings. The `$protection_pair_*` jumps are capped at 200 bytes on purpose: at 512 bytes, a 1 MiB buffer of repeated protection-setup fragments took ~4.6 s in YARA-X 1.23 (~0.08 s at 200).

## Known False Positives

Measured 2026-11-10 with libyara 4.5.4 against **13,546 benign files** (`.dll`, `.exe`, `.sys`, `.ps1`, `.psm1`, `.psd1`, `.hta`, `.vbs`, `.js`) from `System32`, `SysWOW64`, `Microsoft.NET` and PowerShell 7 on Windows 11. Rules not listed produced **zero** matches, including every `core` rule.

| Rule | Benign matches | Examples | Why it matches |
|:-----|:--------------:|:---------|:---------------|
| `CobaltStrike_SleepMask_VirtualProtect` | **110** | `combase.dll`, `lsasrv.dll`, `urlmon.dll`, `dbghelp.dll` | `VirtualProtect`/`Sleep` are imported by most PEs, and the protection-constant/indirect-call pattern is ordinary compiler output (156 with the previous 512-byte gap) |
| `CobaltStrike_SleepMask_RC4_SystemFunction032` | 6 | `KernelBase.dll`, `apphelp.dll`, `netlogon.dll` (x64 + WoW64) | Contain all three API-name strings; PE files that export `SystemFunction032` (e.g. `advapi32.dll`) are excluded |
| `CobaltStrike_ReflectiveLoader_Code` | 1 | `wpfgfx_v0300.dll` | Generic PE-parsing and allocation constants |

The sleep-mask rules are supporting evidence only — corroborate with config-block or stager matches before escalating.

> **Note:** This corpus is clean Microsoft software only. Testing against other offensive frameworks (Metasploit, Sliver, Brute Ratel) and a broad third-party software set has not been performed. Community contributions of FP test results are welcome.

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
├── index.yar                       # Includes every rule file
├── .github/workflows/yara-ci.yml   # CI: libyara + YARA-X test matrix
├── tests/
│   ├── run_tests.py                # Compile + exact-match blob tests
│   └── expected.json               # Expected rules per blob, pending fixtures
├── rules/
│   ├── cs_shellcode_stagers.yar    # Shellcode stager prologues
│   ├── cs_reflective_loader.yar    # Reflective DLL injection
│   ├── cs_beacon_config.yar        # Encoded + decoded beacon configs
│   ├── cs_named_pipes.yar          # SMB beacon & post-ex pipes
│   ├── cs_powershell_loaders.yar   # PowerShell / .NET / HTA loaders
│   ├── cs_sleep_mask.yar           # Sleep mask obfuscation
│   └── cs_watermarks.yar           # Cracked license watermarks
├── samples/
│   └── known_hashes.txt            # Public sample hashes for validation
└── test_blobs/                     # Synthetic test blobs for pattern matching validation
```

## Contributing

Contributions welcome. To add a rule:

1. Fork this repo
2. Add your rule to the appropriate `.yar` file (or create a new one for a new detection surface)
3. Include `meta:` fields: `description`, `author`, `date`, `reference`, `severity`, `tlp` (and `status = "experimental"` for heuristics with no observed true positive)
4. Comment the byte patterns — explain **what** each sequence is in the disassembly
5. Test against at least one known CS sample and one non-CS sample, add any new test blob to `tests/expected.json`, and make sure `python tests/run_tests.py --engine libyara` and `--engine yarax` both pass
6. Open a PR with the sample hash(es) you validated against

## Changelog

### 2026-11-10 — decode-first Quick Start

- Quick Start rewritten around the real workflow: install YARA and `dissect.cobaltstrike`, decode payload files with `beacon-dump` / `beacon-xordecode` before scanning, scan dumps and scripts directly, start with `-t core`, and how to read the results. Added a single-file bundle command for tools that do not follow `include` lines.

### 2026-11-10 — review hardening

**Breaking**

- Removed `CobaltStrike_Shellcode_Stager_Generic`. It required plaintext WinInet names and one exact User-Agent, so it could essentially never match hash-resolving stagers. Update any references to it.
- `CobaltStrike_Watermark_Cracked_Common` now requires the config prefix before the watermark (a standalone 10-byte watermark TLV no longer matches), and watermark `0` moved to the new `CobaltStrike_Watermark_Zero` (severity `high`).

**Added**

- `CobaltStrike_ArtifactKit_Pipe_Format` — default Artifact Kit pipe-name format string in PE files.
- `index.yar`, `tests/run_tests.py`, `tests/expected.json`, CI for libyara and YARA-X.
- [Supported Inputs](#supported-inputs) table, [External Validation](#external-validation) results, and public test-Beacon hashes in `samples/known_hashes.txt`.

**Changed**

- `CobaltStrike_ReflectiveLoader_Export` also matches stdcall-decorated exports (`_ReflectiveLoader@4`).
- `CobaltStrike_Beacon_DLL_Characteristics` checks the parsed export-directory name (`pe.dll_name`) on x86 and x64 instead of free text plus generic return bytes.
- `CobaltStrike_SleepMask_VirtualProtect`: protection-pair gap 512 → 200 bytes (YARA-X stress case ~4.6 s → ~0.08 s per MiB; benign matches 156 → 110); severity `low`.
- `CobaltStrike_SleepMask_RC4_SystemFunction032` excludes PE files that export `SystemFunction032`, without dropping raw dumps.
- `CobaltStrike_SleepMask_XOR_Stub` marked experimental, severity `low`.
- `CobaltStrike_Named_Pipes_Default` no longer has a 50 MB cap, so large dumps and live-process scans are not silently skipped.
- `Generic_DotNet_Assembly_Loader` skips PE files (25 benign matches → 0); `Generic_HTA_VBS_Loader` accepts quote, attribute-order and spacing variations of the VBScript tag.
- `_Embedded` stager rules use a constant-time offset check instead of a loop over every match.
- Documentation corrected throughout: scope, versions, false-positive measurements and comments.

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

#!/usr/bin/env python3
"""Rule-pack regression tests.

Checks, for the chosen engine:
  1. every rules/*.yar file and index.yar compile without errors, and
     index.yar includes every rules/*.yar file;
  2. each test blob matches exactly the rules listed in tests/expected.json;
  3. every rule in the pack is either covered by a positive blob or listed in
     "pending_positive_fixtures" (so coverage gaps stay visible);
  4. no blob exists without an expectation.

Usage:
  python tests/run_tests.py --engine libyara   # needs: pip install yara-python
  python tests/run_tests.py --engine yarax     # needs: pip install yara-x

Exit code is non-zero on any failure.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
BLOBS_DIR = ROOT / "test_blobs"
INDEX = ROOT / "index.yar"
EXPECTED = Path(__file__).resolve().parent / "expected.json"
RULE_DECL = re.compile(r"^\s*rule\s+(\w+)\s*(?::[\w\s]*)?\{", re.MULTILINE)
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"^\s*//[^\n]*", re.MULTILINE)
INCLUDE_DECL = re.compile(r'^\s*include\s+"([^"]+)"', re.MULTILINE)


def declared_rules():
    """Public (non-private) rule names declared across rules/*.yar.

    Comments are stripped first so prose such as "rule excludes ..." inside
    a comment is not mistaken for a declaration.
    """
    names = set()
    for path in sorted(RULES_DIR.glob("*.yar")):
        text = BLOCK_COMMENT.sub("", path.read_text(encoding="utf-8"))
        text = LINE_COMMENT.sub("", text)
        names.update(RULE_DECL.findall(text))
    return names


class LibYara:
    def __init__(self):
        import yara  # noqa: PLC0415

        self.yara = yara

    def compile_file(self, path):
        rules = self.yara.compile(filepath=str(path))
        return [str(w) for w in getattr(rules, "warnings", [])]

    def load_pack(self):
        self.rules = self.yara.compile(filepath=str(INDEX))

    def match(self, path):
        return {m.rule for m in self.rules.match(str(path), timeout=60)}


class YaraX:
    def __init__(self):
        import yara_x  # noqa: PLC0415

        self.yara_x = yara_x

    def _compiler(self):
        # include "rules/..." in index.yar is resolved relative to the repo root.
        compiler = self.yara_x.Compiler(includes_enabled=True)
        compiler.add_include_dir(str(ROOT))
        return compiler

    def compile_file(self, path):
        compiler = self._compiler()
        compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
        warnings = [w.get("title", str(w)) for w in compiler.warnings()]
        compiler.build()
        return warnings

    def load_pack(self):
        compiler = self._compiler()
        compiler.add_source(INDEX.read_text(encoding="utf-8"), origin=str(INDEX))
        self.scanner = self.yara_x.Scanner(compiler.build())

    def match(self, path):
        result = self.scanner.scan(path.read_bytes())
        return {r.identifier for r in result.matching_rules}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=("libyara", "yarax"), required=True)
    args = parser.parse_args()

    engine = LibYara() if args.engine == "libyara" else YaraX()
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    failures = []

    for path in sorted(RULES_DIR.glob("*.yar")) + [INDEX]:
        try:
            for warning in engine.compile_file(path):
                print(f"WARN  {path.name}: {warning}")
            print(f"OK    compile {path.name}")
        except Exception as exc:  # engine-specific error types
            failures.append(f"compile {path.name}: {exc}")

    included = set(INCLUDE_DECL.findall(INDEX.read_text(encoding="utf-8")))
    for path in sorted(RULES_DIR.glob("*.yar")):
        if f"rules/{path.name}" not in included:
            failures.append(f"index.yar does not include rules/{path.name}")

    if failures:
        report(failures)

    engine.load_pack()
    blob_expect = expected["blobs"]
    on_disk = {p.name for p in BLOBS_DIR.iterdir() if p.is_file()}

    for name in sorted(on_disk - set(blob_expect)):
        failures.append(f"blob {name} has no entry in tests/expected.json")
    for name in sorted(set(blob_expect) - on_disk):
        failures.append(f"expected.json lists missing blob {name}")

    for name in sorted(on_disk & set(blob_expect)):
        got = engine.match(BLOBS_DIR / name)
        want = set(blob_expect[name])
        if got == want:
            print(f"OK    {name} -> {sorted(got) or '-'}")
        else:
            failures.append(
                f"{name}: missing={sorted(want - got)} unexpected={sorted(got - want)}"
            )

    all_rules = declared_rules()
    covered = {r for rules in blob_expect.values() for r in rules}
    pending = set(expected.get("pending_positive_fixtures", []))
    for rule in sorted(all_rules - covered - pending):
        failures.append(f"rule {rule} has no positive blob and is not listed as pending")
    for rule in sorted((covered | pending) - all_rules):
        failures.append(f"expected.json references unknown rule {rule}")
    for rule in sorted(covered & pending):
        failures.append(f"rule {rule} is covered but still listed as pending")

    print(f"\nPositive fixtures: {len(covered)}/{len(all_rules)} rules; "
          f"{len(pending)} pending")
    report(failures)


def report(failures):
    if failures:
        print("\nFAILURES:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()

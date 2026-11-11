#!/usr/bin/env python3
"""Check that every sample-security-radar blob link in the docs points to an existing file and line.

Usage: python3 scripts/check_source_links.py <path-to-local-sample-security-radar-clone>
The clone must be at the commit the docs pin (7d5362e).
"""
import pathlib
import re
import sys

LINK = re.compile(r"github\.com/aws-samples/sample-security-radar/blob/([0-9a-f]+)/([^)#\s`]+)(?:#L(\d+)(?:-L(\d+))?)?")
# Bare citations such as `src/radar/respond.py:120`, `src/radar/limits.py:10-21` or `infra/stack.py#L40`.
CITE = re.compile(r"(?<![\w/])((?:src|infra|scripts|tests|integrations|ui|schemas)/[\w./-]+\.\w+)(?::|#L)(\d+)(?:-L?(\d+))?")


def main() -> int:
    src = pathlib.Path(sys.argv[1])
    root = pathlib.Path(__file__).resolve().parent.parent
    bad, total = [], 0
    for doc in sorted(root.rglob("*.md")):
        for n, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            hits = [(p, a, b) for _, p, a, b in LINK.findall(line)]
            # Bare `path:line` citations refer to the radar source only in the ai4security docs.
            if doc.relative_to(root).parts[0] == "ai4security" and "sample-security-radar/blob/" not in line:
                hits += CITE.findall(line)
            for path, a, b in hits:
                total += 1
                f = src / path
                where = f"{doc.relative_to(root)}:{n}"
                if not f.exists():
                    bad.append(f"{where}: missing file {path}")
                    continue
                if f.is_dir():
                    continue
                count = len(f.read_text(encoding="utf-8", errors="replace").splitlines())
                for ln in (a, b):
                    if ln and int(ln) > count:
                        bad.append(f"{where}: {path}#L{ln} beyond {count} lines")
    print(f"checked {total} links, {len(bad)} bad")
    print("\n".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

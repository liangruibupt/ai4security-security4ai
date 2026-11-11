#!/usr/bin/env python3
"""Print a random sample of doc citations next to the source line they point at, for manual review.

Usage: python3 scripts/sample_citations.py <path-to-local-sample-security-radar-clone> [count]
"""
import pathlib
import random
import re
import sys

LINK = re.compile(r"\[([^\]]{3,80})\]\(https://github\.com/aws-samples/sample-security-radar/blob/[0-9a-f]+/([^)#]+)#L(\d+)")


def main() -> None:
    src = pathlib.Path(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    root = pathlib.Path(__file__).resolve().parent.parent
    hits = [m for doc in root.rglob("*.md") for m in LINK.findall(doc.read_text(encoding="utf-8"))]
    random.seed(7)
    for text, path, line in random.sample(hits, min(count, len(hits))):
        lines = (src / path).read_text(encoding="utf-8", errors="replace").splitlines()
        print(f"DOC  {text}\nSRC  {path}:{line}: {lines[int(line) - 1].strip()[:120]}\n")


if __name__ == "__main__":
    main()

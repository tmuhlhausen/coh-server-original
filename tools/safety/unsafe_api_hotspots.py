#!/usr/bin/env python3
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXTS = {".c", ".h", ".cpp", ".hpp"}
PATTERN = re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(")

rows = []
for path in ROOT.rglob("*"):
    if path.suffix.lower() not in EXTS:
        continue
    if any(part in {".git", "3rdparty", "AuthServer/external"} for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    lines = text.count("\n") + 1
    hits = len(PATTERN.findall(text))
    if hits:
        density = (hits / max(lines, 1)) * 1000.0
        rows.append((density, hits, lines, str(path.relative_to(ROOT))))

rows.sort(reverse=True)
print("rank,density_per_kloc,unsafe_calls,lines,file")
for idx, (density, hits, lines, rel) in enumerate(rows[:200], start=1):
    print(f"{idx},{density:.2f},{hits},{lines},{rel}")

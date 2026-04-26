#!/usr/bin/env python3
import re
import subprocess
import sys

BANNED = ["gets", "strcpy", "strcat", "sprintf", "vsprintf"]
PATTERN = re.compile(r"\b(" + "|".join(BANNED) + r")\s*\(")


def run(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def main():
    diff_cmd = ["git", "diff", "--unified=0", "--", "*.c", "*.h", "*.cpp", "*.hpp"]
    if len(sys.argv) > 1:
        diff_cmd = ["git", "diff", "--unified=0", sys.argv[1], "--", "*.c", "*.h", "*.cpp", "*.hpp"]

    diff = run(diff_cmd)
    cur_file = ""
    failures = []

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            m = PATTERN.search(line)
            if m:
                failures.append((cur_file, m.group(1), line[1:].strip()))

    if failures:
        print("Unsafe API usage introduced in added lines:")
        for file_path, api, snippet in failures:
            print(f" - {file_path}: {api} -> {snippet}")
        return 1

    print("No new unsafe API usage found in added lines.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

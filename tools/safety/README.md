# Safe string migration tooling

## CI lint gate

Block new unsafe API usage in added lines:

```bash
.ci/safe_str_lint_gate.sh [<git-diff-base>]
```

Unsafe APIs blocked: `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`.

## Hotspot ranking

Generate top-200 unsafe-call density report:

```bash
python3 tools/safety/unsafe_api_hotspots.py
```

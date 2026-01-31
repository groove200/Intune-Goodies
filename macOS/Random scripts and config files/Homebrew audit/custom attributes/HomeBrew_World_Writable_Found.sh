#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("world_writable_found",0))
except Exception:
  print(0)
PY
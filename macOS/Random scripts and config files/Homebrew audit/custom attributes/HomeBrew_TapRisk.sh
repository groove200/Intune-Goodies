#!/bin/bash
python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
try:
  d=json.load(open(p))
  print(d.get("tap_risk","Low"))
except Exception:
  print("Low")
PY
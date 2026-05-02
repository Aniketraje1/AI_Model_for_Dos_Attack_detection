import json
import traceback
from pathlib import Path

NB_PATH = Path(r"C:\Users\anike\Downloads\Live_Wireshark_UNSW_Inference.ipynb")


def _is_side_effect_cell(code: str) -> bool:
    if "def run_live_monitor" in code:
        return False
    if "run_live_monitor()" in code:
        return True
    return False


ns = {}
nb = json.loads(NB_PATH.read_text(encoding="utf-8"))
for idx, cell in enumerate(nb.get("cells", [])):
    if cell.get("cell_type") != "code":
        continue
    code = "".join(cell.get("source", []))
    if _is_side_effect_cell(code):
        continue
    exec(compile(code, f"cell_{idx}", "exec"), ns, ns)

print("LIVE_MONITOR_START", flush=True)
try:
    ns["run_live_monitor"]()
except KeyboardInterrupt:
    print("LIVE_MONITOR_STOPPED", flush=True)
except Exception:
    traceback.print_exc()

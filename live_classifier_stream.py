import json
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import ipaddress


NB_PATH = Path(r"C:\Users\anike\Downloads\Live_Wireshark_UNSW_Inference.ipynb")
DEFAULT_MODEL_DIR = Path(r"C:\Users\anike\Downloads\Attack datasets\rogueshield_outputs")
LIVE_TUNED_MODEL_NAME = "intrusion_classifier_live_tuned.keras"
CAPTURE_DIR = Path(r"C:\Users\anike\Downloads\captures")
PRED_LOG = CAPTURE_DIR / "classification_live.log"
PRED_CSV = CAPTURE_DIR / "classification_live.csv"
POLL_SECONDS = 2
TOP_ROWS_PER_FILE = 5
FILE_READY_AGE_SEC = 3
NORMAL_CLASS_LABEL = "Normal"
DOS_CLASS_KEYWORDS = ("dos", "ddos")
DOS_CONFIDENCE_THRESHOLD = 0.70
OTHER_ATTACK_CONFIDENCE_THRESHOLD = 0.90
WHITELIST_PORTS = {53, 5353, 1900}
WHITELIST_IPS = {"224.0.0.251", "239.255.255.250"}
DOS_MIN_SRC_FLOWS_PER_FILE = 12
# Fallback DoS gate when src flow fan-out is low:
# require a much stronger confidence + traffic spike to reduce false positives
# from normal high-throughput traffic (for example QUIC/HTTPS bursts).
DOS_STRICT_CONFIDENCE_THRESHOLD = 0.90
DOS_MIN_TOTAL_PACKETS = 3000
DOS_MIN_PACKETS_PER_SEC = 8000.0


def _is_side_effect_cell(code: str) -> bool:
    """Skip notebook cells that start interactive monitor loops."""
    if "def run_live_monitor" in code:
        return False
    if "run_live_monitor()" in code:
        return True
    return False


def load_notebook_namespace(nb_path: Path):
    nb = json.loads(nb_path.read_text(encoding="utf-8"))
    ns = {}
    for idx, cell in enumerate(nb.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        code = "".join(cell.get("source", []))
        if _is_side_effect_cell(code):
            continue
        exec(compile(code, f"cell_{idx}", "exec"), ns, ns)
    if "score_pcap_file" not in ns:
        raise KeyError("score_pcap_file was not found after loading notebook cells")
    return ns


def log_line(msg: str):
    stamp = datetime.now().isoformat(timespec="seconds")
    line = f"[{stamp}] {msg}"
    print(line, flush=True)
    with PRED_LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def append_predictions(df: pd.DataFrame):
    write_header = not PRED_CSV.exists()
    df.to_csv(PRED_CSV, mode="a", header=write_header, index=False)


def _safe_port(value) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0


def _is_normal_class(label: str) -> bool:
    return str(label).strip().casefold() == NORMAL_CLASS_LABEL.casefold()


def _required_alert_confidence(label: str) -> float:
    label_norm = str(label).strip().casefold()
    if any(token in label_norm for token in DOS_CLASS_KEYWORDS):
        return DOS_CONFIDENCE_THRESHOLD
    return OTHER_ATTACK_CONFIDENCE_THRESHOLD


def _whitelist_mask(df: pd.DataFrame) -> pd.Series:
    dst_ip = (
        df["dst_ip"] if "dst_ip" in df.columns else pd.Series("", index=df.index, dtype="object")
    )
    src_ip = (
        df["src_ip"] if "src_ip" in df.columns else pd.Series("", index=df.index, dtype="object")
    )
    dst_port = (
        df["dst_port"] if "dst_port" in df.columns else pd.Series(-1, index=df.index, dtype="float64")
    )

    dst_ip = dst_ip.fillna("").astype(str).str.strip()
    src_ip = src_ip.fillna("").astype(str).str.strip()
    dst_port = pd.to_numeric(dst_port, errors="coerce").fillna(-1).astype("int64")

    def _is_multicast(ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_multicast
        except Exception:
            return False

    dst_multicast = dst_ip.map(_is_multicast)
    src_multicast = src_ip.map(_is_multicast)

    return (
        dst_port.isin(WHITELIST_PORTS)
        | dst_ip.isin(WHITELIST_IPS)
        | src_ip.isin(WHITELIST_IPS)
        | dst_multicast
        | src_multicast
    )


def main():
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    ns = load_notebook_namespace(NB_PATH)
    model_dir = Path(ns.get("MODEL_DIR", DEFAULT_MODEL_DIR))
    tuned_model_path = model_dir / LIVE_TUNED_MODEL_NAME
    if tuned_model_path.exists():
        tf_mod = ns.get("tf")
        if tf_mod is not None:
            try:
                ns["model"] = tf_mod.keras.models.load_model(tuned_model_path)
            except Exception as e:
                log_line(f"Failed to load tuned model {tuned_model_path}: {type(e).__name__}: {e}")
            else:
                log_line(f"Loaded tuned model: {tuned_model_path}")
    score_pcap_file = ns["score_pcap_file"]

    # Start from "now": existing pcap files are treated as historical.
    processed = {str(p) for p in CAPTURE_DIR.glob("*.pcap*")}
    size_seen = {}

    log_line(f"Classifier started. Watching {CAPTURE_DIR}")
    log_line("Skipping existing pcap files; only new chunks will be processed.")

    while True:
        now = time.time()
        files = sorted(
            [p for p in CAPTURE_DIR.glob("*.pcap*") if p.is_file()],
            key=lambda p: p.stat().st_mtime,
        )
        new_files = [p for p in files if str(p) not in processed]

        for p in new_files:
            pkey = str(p)

            # Avoid reading files that are likely still being written by dumpcap.
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            if now - st.st_mtime < FILE_READY_AGE_SEC:
                continue

            # Require two consecutive polls with same size before processing.
            prev_size = size_seen.get(pkey)
            size_seen[pkey] = st.st_size
            if prev_size is None or prev_size != st.st_size:
                continue

            try:
                scored = score_pcap_file(p)
                if scored.empty:
                    log_line(f"{p.name}: no classified flows")
                    processed.add(pkey)
                    size_seen.pop(pkey, None)
                    continue

                keep_cols = [
                    "pcap_file",
                    "flow_id",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "proto",
                    "service",
                    "pred_attack_cat",
                    "confidence",
                    "dur",
                    "spkts",
                    "dpkts",
                ]
                cols = [c for c in keep_cols if c in scored.columns]
                out = scored[cols].copy()
                out.insert(0, "event_time", datetime.now().isoformat(timespec="seconds"))
                append_predictions(out)

                labels = out["pred_attack_cat"].fillna("").astype(str)
                conf = pd.to_numeric(out["confidence"], errors="coerce").fillna(0.0)
                required_conf = labels.map(_required_alert_confidence)
                is_normal = labels.map(_is_normal_class)
                is_whitelisted = _whitelist_mask(out)
                is_dos = labels.str.contains("dos", case=False, na=False)

                src_ip = out["src_ip"].fillna("").astype(str)
                src_flow_count = src_ip.map(src_ip.value_counts()).fillna(0).astype("int64")
                spkts = pd.to_numeric(
                    out["spkts"] if "spkts" in out.columns else pd.Series(0, index=out.index),
                    errors="coerce",
                ).fillna(0.0)
                dpkts = pd.to_numeric(
                    out["dpkts"] if "dpkts" in out.columns else pd.Series(0, index=out.index),
                    errors="coerce",
                ).fillna(0.0)
                dur = pd.to_numeric(
                    out["dur"] if "dur" in out.columns else pd.Series(0.0, index=out.index),
                    errors="coerce",
                ).fillna(0.0).clip(lower=0.001)
                total_packets = spkts + dpkts
                pps = total_packets / dur

                dos_behavior = (
                    (src_flow_count >= DOS_MIN_SRC_FLOWS_PER_FILE)
                    | (
                        (total_packets >= DOS_MIN_TOTAL_PACKETS)
                        & (pps >= DOS_MIN_PACKETS_PER_SEC)
                        & (conf >= DOS_STRICT_CONFIDENCE_THRESHOLD)
                    )
                )

                base_candidate = (~is_normal) & (~is_whitelisted) & (conf >= required_conf)
                dos_candidate = base_candidate & is_dos
                non_dos_alert = base_candidate & (~is_dos)
                dos_alert = dos_candidate & dos_behavior

                alerts = out.loc[non_dos_alert | dos_alert].copy()
                alerts["total_packets"] = total_packets.loc[alerts.index]
                alerts["pps"] = pps.loc[alerts.index]
                alerts["src_flow_count"] = src_flow_count.loc[alerts.index]
                alerts = alerts.sort_values("confidence", ascending=False)

                suppressed_whitelist = int(((~is_normal) & is_whitelisted).sum())
                suppressed_dos_behavior = int((dos_candidate & (~dos_behavior)).sum())

                log_line(
                    f"{p.name}: flows={len(out)} attack_alerts={len(alerts)} "
                    f"suppressed_whitelist={suppressed_whitelist} suppressed_dos_behavior={suppressed_dos_behavior} "
                    f"thresholds=DoS/DDoS>={DOS_CONFIDENCE_THRESHOLD:.2f}, "
                    f"others>={OTHER_ATTACK_CONFIDENCE_THRESHOLD:.2f} "
                    f"dos_behavior=(src_flows>={DOS_MIN_SRC_FLOWS_PER_FILE} or "
                    f"(pkts>={DOS_MIN_TOTAL_PACKETS} and pps>={DOS_MIN_PACKETS_PER_SEC:.0f} "
                    f"and conf>={DOS_STRICT_CONFIDENCE_THRESHOLD:.2f})) "
                    f"whitelist_ports={sorted(WHITELIST_PORTS)} whitelist_ips={sorted(WHITELIST_IPS)}"
                )
                top_alerts = alerts.head(TOP_ROWS_PER_FILE)
                for _, r in top_alerts.iterrows():
                    src_port = _safe_port(r.get("src_port", 0))
                    dst_port = _safe_port(r.get("dst_port", 0))
                    log_line(
                        f"  ATTACK class={r.get('pred_attack_cat')} conf={float(r.get('confidence', 0)):.3f} "
                        f"src_flows={int(float(r.get('src_flow_count', 0)))} "
                        f"pkts={float(r.get('total_packets', 0)):.0f} pps={float(r.get('pps', 0)):.1f} "
                        f"{r.get('src_ip')}:{src_port}->{r.get('dst_ip')}:{dst_port} "
                        f"proto={r.get('proto')} service={r.get('service')}"
                    )
                processed.add(pkey)
                size_seen.pop(pkey, None)
            except Exception as e:
                msg = str(e).lower()
                if "cut short in the middle of a packet" in msg:
                    # File is still being finalized; retry next cycle.
                    continue
                log_line(f"{p.name}: ERROR {type(e).__name__}: {e}")
                processed.add(pkey)
                size_seen.pop(pkey, None)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

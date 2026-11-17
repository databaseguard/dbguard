#!/usr/bin/env bash
# =============================================================================
# show-verdicts.sh - print the firewall verdict for each audited query in a
# readable table. Robust where grep/jq one-liners fail (reads every JSONL line
# with Python, handles root-owned audit files).
#
# Usage:
#   sudo ./scripts/show-verdicts.sh [N] [filter]
#     N       how many recent rows to show (default 20)
#     filter  only rows whose SQL contains this text (optional)
#
# Examples:
#   sudo ./scripts/show-verdicts.sh 20
#   sudo ./scripts/show-verdicts.sh 50 secrets
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
N="${1:-20}"; FILTER="${2:-}"
AUDIT="${DBGUARD_AUDIT_DIR:-.dbguard-state/audit}"

python3 - "$AUDIT" "$N" "$FILTER" <<'PY'
import sys, glob, json, os
d, n, filt = sys.argv[1], int(sys.argv[2]), (sys.argv[3] if len(sys.argv) > 3 else "")
rows = []
for fn in sorted(glob.glob(os.path.join(d, "*.jsonl"))):
    try:
        for line in open(fn):
            try:
                e = json.loads(line)
            except Exception:
                continue
            sql = (e.get("sql") or "")
            if filt and filt.lower() not in sql.lower():
                continue
            rows.append((
                (e.get("time") or "")[11:19],
                "ALLOW" if e.get("allowed") else "DENY ",
                (e.get("rule_id") or "-"),
                (e.get("type") or ""),
                sql[:48],
            ))
    except OSError:
        pass
rows = rows[-n:]
if not rows:
    print("(no matching audit records - is the daemon running and are queries being captured?)")
else:
    print("%-8s  %-5s  %-20s  %-16s  %s" % ("TIME", "V", "RULE", "TYPE", "SQL"))
    print("-" * 90)
    for t, v, rule, typ, sql in rows:
        print("%-8s  %-5s  %-20s  %-16s  %s" % (t, v, rule, typ, sql))
    na = sum(1 for r in rows if r[1] == "ALLOW")
    nd = sum(1 for r in rows if r[1] == "DENY ")
    print("-" * 90)
    print("allowed=%d  denied=%d" % (na, nd))
PY

"""Compute DCI, Neff, and anomaly class distribution from existing files.
Read-only. No agent execution, no LLM call. Usage:
    python compute_kpis.py <policy.yaml> <results.json>
"""
import sys, json, time, yaml

def main(policy_path, results_path):
    t0 = time.time()

    with open(policy_path, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    enabled_ids = {r["id"] for r in policy["rules"] if r.get("enabled", True)}

    with open(results_path, encoding="utf-8") as f:
        results = json.load(f)

    E, F, A = {}, {}, {}
    for case in results["results"]:
        for d in case.get("decisions", []):
            name = d["name"]
            E[name] = E.get(name, 0) + 1
            if d.get("triggered"):
                F[name] = F.get(name, 0) + 1
        blocker = case.get("blocked_by")
        if blocker:
            A[blocker] = A.get(blocker, 0) + 1

    # classify every enabled rule
    classes = {"cross_hook_shadowed": [], "never_triggered": [],
               "attribution_shadowed": [], "load_bearing": []}
    for rid in sorted(enabled_ids):
        e, fi, a = E.get(rid, 0), F.get(rid, 0), A.get(rid, 0)
        if e == 0:
            classes["cross_hook_shadowed"].append(rid)
        elif fi == 0:
            classes["never_triggered"].append(rid)
        elif a == 0:
            classes["attribution_shadowed"].append(rid)
        else:
            classes["load_bearing"].append(rid)

    total_attrib = sum(A.values())
    dci = sum((n / total_attrib) ** 2 for n in A.values()) if total_attrib else 0.0
    neff = (1 / dci) if dci else 0.0

    elapsed = time.time() - t0

    print(f"Enabled rules: {len(enabled_ids)}")
    print(f"Determined cases (total attribution events): {total_attrib}")
    print()
    for rid in sorted(A, key=A.get, reverse=True):
        print(f"  {rid:30s} attributed {A[rid]:3d}x  ({A[rid]/total_attrib:.1%})")
    print()
    print(f"DCI  = {dci:.4f}")
    print(f"Neff = {neff:.2f}   (of {len(enabled_ids)} enabled rules)")
    print()
    for cls, ids in classes.items():
        print(f"{cls:22s} ({len(ids)}): {', '.join(ids) if ids else '-'}")
    print()
    print(f"Analysis overhead: {elapsed*1000:.1f} ms, 0 LLM calls, $0.00")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

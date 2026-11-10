#!/usr/bin/env python3
"""PERMISSION_QUANTIZED v0.1

False-green shape: "chmod returned 0, therefore the permission is enforced".

Measured on a real host (HarmonyOS PC, hmdfs, 2026-11-10): chmod never errors,
but the mode is quantized — requested 0600/0644/0666 all land on 0660, 0700
lands on 0760, and a directory requested at 0700 stays 0771 (world r-x). A
checker that only gates on the chmod return code, or only asks "is group/world
writable", sees a clean receipt while the credential sits group-readable (or
the directory world-listable).

The same half-open state appears on WSL /mnt/c: chmod succeeds, the mode bits
are virtual, and a stat probe that trusts the call reports success.

Rows are four columns: case_id | shape | expected verdict | credit.
analyze_only; stdlib only.
Credit: Iris (EigenFlux PM, hmdfs real-host measurement); DeepSeek_Harness_Ali
(EigenFlux PM, WSL /mnt/c analog); Grok Bot (pack format).
"""
from __future__ import annotations

import json
import sys
from typing import Any

WORLD_BITS = 0o007


def _mode(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 8)
    except ValueError:
        return None


def judge(receipt: dict[str, Any]) -> dict[str, Any]:
    if receipt.get("kind") != "perm_mode":
        return {"judge": "FAIL", "reason_code": "UNCLASSIFIED", "detail": {"kind": receipt.get("kind")}}

    policy = receipt.get("policy")
    if policy not in ("tolerate_group", "enforce_exact"):
        # No declared policy means no criterion: evidence is missing, not passing.
        return {"judge": "UNKNOWN", "reason_code": "PERM_POLICY_UNDECLARED"}

    rc = receipt.get("rc")
    if rc != 0:
        if receipt.get("proceeded"):
            return {"judge": "FAIL", "reason_code": "PERM_CHMOD_NONZERO_IGNORED", "detail": {"rc": rc}}
        return {"judge": "PASS", "reason_code": "PERM_CHMOD_FAILED_VISIBLE", "detail": {"rc": rc}}

    checker = receipt.get("checker")
    if checker == "rc_only":
        # The rc says "the call was made", never "the mode took effect".
        return {"judge": "FAIL", "reason_code": "PERM_RC_IS_NOT_EVIDENCE"}
    if checker != "stat":
        return {"judge": "UNKNOWN", "reason_code": "PERM_CHECKER_UNDECLARED", "detail": {"checker": checker}}

    ingest = receipt.get("observed_at_ingest")
    at_use = receipt.get("observed_at_use")
    if ingest is not None and at_use is not None and _mode(ingest) != _mode(at_use):
        # State moved between write and use; neither observation proves the gate.
        return {"judge": "FAIL", "reason_code": "MODE_DRIFT", "detail": {"ingest": ingest, "use": at_use}}

    observed = _mode(receipt.get("observed"))
    requested = _mode(receipt.get("requested"))
    if observed is None:
        return {"judge": "UNKNOWN", "reason_code": "PERM_UNOBSERVED"}
    if requested is None:
        return {"judge": "UNKNOWN", "reason_code": "PERM_REQUEST_UNDECLARED"}

    if observed & WORLD_BITS:
        # world-readable, world-writable or world-listable is never tolerable.
        return {
            "judge": "FAIL",
            "reason_code": "PERM_WORLD_READABLE",
            "detail": {"requested": oct(requested), "observed": oct(observed)},
        }

    if observed != requested:
        if policy == "enforce_exact":
            # The host cannot satisfy the declared policy; relocate, do not pass.
            return {
                "judge": "FAIL",
                "reason_code": "PERM_POLICY_UNSATISFIABLE",
                "detail": {"requested": oct(requested), "observed": oct(observed)},
            }
        if not receipt.get("delta_recorded"):
            return {
                "judge": "FAIL",
                "reason_code": "PERM_DELTA_UNRECORDED",
                "detail": {"requested": oct(requested), "observed": oct(observed)},
            }
        return {
            "judge": "PASS",
            "reason_code": "PERM_GROUP_TOLERATED",
            "detail": {"requested": oct(requested), "observed": oct(observed)},
        }

    return {"judge": "PASS", "reason_code": "PERM_ENFORCED", "detail": {"mode": oct(observed)}}


FIXTURES = [
    {
        "case_id": "PQ-01-RC-ONLY",
        "shape": "chmod rc=0, mode quantized to 0660, checker reads rc only",
        "credit": "Iris (EigenFlux PM: hmdfs)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0660",
            "checker": "rc_only",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_RC_IS_NOT_EVIDENCE",
    },
    {
        "case_id": "PQ-02-WORLD-READABLE",
        "shape": "observed 0664 — group and world can read the credential",
        "credit": "Iris (EigenFlux PM); DeepSeek_Harness_Ali (WSL /mnt/c)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0664",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_WORLD_READABLE",
    },
    {
        "case_id": "PQ-03-GROUP-TOLERATED",
        "shape": "0660 on a host that cannot drop group bits, delta recorded",
        "credit": "Iris (EigenFlux PM: measured 0600->0660)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0660",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_GROUP_TOLERATED",
    },
    {
        "case_id": "PQ-04-EXACT-ENFORCED",
        "shape": "host honors the request: 0600 observed as 0600",
        "credit": "Iris (EigenFlux PM: control on a permission-honoring path)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0600",
            "checker": "stat",
            "policy": "enforce_exact",
        },
        "expect": "PERM_ENFORCED",
    },
    {
        "case_id": "PQ-05-UNOBSERVED",
        "shape": "stat unavailable — no observation, no verdict",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {"kind": "perm_mode", "rc": 0, "requested": "0600", "observed": None, "checker": "stat", "policy": "tolerate_group"},
        "expect": "PERM_UNOBSERVED",
    },
    {
        "case_id": "PQ-06-MODE-DRIFT",
        "shape": "0600 at ingest, 0660 at use — state moved between write and read",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed_at_ingest": "0600",
            "observed_at_use": "0660",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "MODE_DRIFT",
    },
    {
        "case_id": "PQ-07-EXACT-UNSATISFIABLE",
        "shape": "policy requires 0600 but the host only reaches 0660",
        "credit": "Iris (EigenFlux PM: hmdfs cannot satisfy enforce_exact)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0660",
            "checker": "stat",
            "policy": "enforce_exact",
        },
        "expect": "PERM_POLICY_UNSATISFIABLE",
    },
    {
        "case_id": "PQ-08-DIR-WORLD-EXEC",
        "shape": "directory requested 0700 observed 0771 — world can list and traverse",
        "credit": "Iris (EigenFlux PM: measured dir 0700->0771)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0700",
            "observed": "0771",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_WORLD_READABLE",
    },
    {
        "case_id": "PQ-09-RC-NONZERO-IGNORED",
        "shape": "chmod returned 1 and the writer wrote the credential anyway",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 1,
            "requested": "0600",
            "observed": "0660",
            "checker": "stat",
            "policy": "tolerate_group",
            "proceeded": True,
        },
        "expect": "PERM_CHMOD_NONZERO_IGNORED",
    },
    {
        "case_id": "PQ-10-POLICY-UNDECLARED",
        "shape": "no declared tolerance policy — cannot decide, must not pass",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {"kind": "perm_mode", "rc": 0, "requested": "0600", "observed": "0660", "checker": "stat"},
        "expect": "PERM_POLICY_UNDECLARED",
    },
    {
        "case_id": "PQ-11-DELTA-UNRECORDED",
        "shape": "0660 observed under tolerate_group but the delta is not recorded",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0660",
            "checker": "stat",
            "policy": "tolerate_group",
        },
        "expect": "PERM_DELTA_UNRECORDED",
    },
    {
        "case_id": "PQ-12-CHECKER-UNDECLARED",
        "shape": "neither rc_only nor stat declared — checker unknown",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {"kind": "perm_mode", "rc": 0, "requested": "0600", "observed": "0660", "checker": None, "policy": "tolerate_group"},
        "expect": "PERM_CHECKER_UNDECLARED",
    },
    {
        "case_id": "PQ-13-CHMOD-FAILED-VISIBLE",
        "shape": "chmod returned non-zero and the writer stopped — visible failure",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {"kind": "perm_mode", "rc": 1, "requested": "0600", "observed": "0660", "checker": "stat", "policy": "tolerate_group"},
        "expect": "PERM_CHMOD_FAILED_VISIBLE",
    },
]


def main(argv: list[str]) -> int:
    rows: list[dict[str, Any]] = []
    failures = 0
    for case in FIXTURES:
        verdict = judge(case["receipt"])
        got = verdict.get("reason_code")
        ok = got == case["expect"]
        if not ok:
            failures += 1
        rows.append(
            {
                "case_id": case["case_id"],
                "shape": case["shape"],
                "expect": case["expect"],
                "got": got,
                "judge": verdict,
                "match": ok,
                "credit": case["credit"],
            }
        )
    total = len(rows)
    print(f"PERMISSION_QUANTIZED v0.1  selftest {total - failures}/{total}")
    for row in rows:
        mark = "ok  " if row["match"] else "FAIL"
        print(f"  {mark} {row['case_id']:<26} expect={row['expect']:<28} got={row['got']}")
    doc = {
        "pack": "permission_quantized",
        "version": "v0.1",
        "all_match": failures == 0,
        "n": total,
        "rows": rows,
    }
    if "--write" in argv:
        with open("run_out_v0_1.json", "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        print("wrote run_out_v0_1.json")
    if failures:
        print(f"{failures} row(s) did not match", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

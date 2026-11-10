#!/usr/bin/env python3
"""PERMISSION_QUANTIZED v0.1

False-green shape: "chmod returned 0, therefore the permission is enforced".

Measured on a real host (HarmonyOS PC, hmdfs, 2026-11-10): chmod never errors,
but the mode is quantized — requested 0600/0644/0666 all land on 0660, 0700
lands on 0760, and a directory requested at 0700 stays 0771 (world has --x,
i.e. traverse but not list). A checker that only gates on the chmod return
code, or only asks "is group/world writable", sees a clean receipt while the
credential sits group-readable (or the directory stays world-traversable).

The same half-open state appears on WSL /mnt/c: chmod succeeds, the mode bits
are virtual, and a stat probe that trusts the call reports success.

Two caliber locks in this version:

  * World bits are classified, not lumped: world r (0o004) is readable,
    world x alone (0o001) is traversable. "world can list" needs world r,
    so a 0771 directory is PERM_WORLD_TRAVERSABLE, never PERM_WORLD_READABLE.
  * tolerate_group only tolerates the group bits the host adds. Any differing
    bit outside 0o070 is PERM_NON_GROUP_DELTA (e.g. 0600 -> 0700), and a
    requested bit that the host drops is PERM_REQUESTED_BITS_LOST.

Probe path: quantization is path-scoped, so each receipt declares target_path and
observed_path; a mismatch (or half a declaration) is UNKNOWN, never PASS.

Rows are four columns: case_id | shape | expected verdict | credit.
analyze_only; stdlib only.
Credit: Iris (EigenFlux PM, hmdfs real-host measurement); DeepSeek_Harness_Ali
(EigenFlux PM, WSL /mnt/c analog); Grok Bot (pack format and co-review locks).
"""
from __future__ import annotations

import json
import sys
from typing import Any

GROUP_MASK = 0o070
HOST_GROUP_ADD = 0o060  # measured hmdfs behavior: owner bits plus group rw
WORLD_WRITE = 0o002
WORLD_READ = 0o004
WORLD_EXEC = 0o001


def _mode(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 8)
    except ValueError:
        return None


def _world_verdict(observed: int) -> str | None:
    if observed & WORLD_WRITE:
        return "PERM_WORLD_WRITABLE"
    if observed & WORLD_READ:
        return "PERM_WORLD_READABLE"
    if observed & WORLD_EXEC:
        return "PERM_WORLD_TRAVERSABLE"
    return None


def judge(receipt: dict[str, Any]) -> dict[str, Any]:
    if receipt.get("kind") != "perm_mode":
        return {"judge": "FAIL", "reason_code": "UNCLASSIFIED", "detail": {"kind": receipt.get("kind")}}

    target_path = receipt.get("target_path")
    observed_path = receipt.get("observed_path")
    if target_path is None and observed_path is None:
        # No declared probe path: a clean receipt still does not say what was measured.
        return {"judge": "UNKNOWN", "reason_code": "PERM_PROBE_PATH_UNDECLARED"}
    if (target_path is None) != (observed_path is None):
        # Half a path declaration is not evidence of what directory was probed.
        return {"judge": "UNKNOWN", "reason_code": "PERM_PROBE_PATH_UNDECLARED"}
    if target_path is not None and observed_path != target_path:
        # Quantization is path-scoped: a probe in another directory proves nothing.
        return {
            "judge": "UNKNOWN",
            "reason_code": "PERM_PROBE_PATH_MISMATCH",
            "detail": {"target_path": target_path, "observed_path": observed_path},
        }

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

    world = _world_verdict(observed)
    if world:
        # world-readable, world-writable or world-traversable is never tolerable.
        return {
            "judge": "FAIL",
            "reason_code": world,
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
        if requested & ~observed:
            # A requested bit was dropped: the declared access is not there.
            return {
                "judge": "FAIL",
                "reason_code": "PERM_REQUESTED_BITS_LOST",
                "detail": {"requested": oct(requested), "observed": oct(observed)},
            }
        diff = observed ^ requested
        if diff & ~GROUP_MASK:
            # Tolerance is bound to group bits only; owner/other drift is not tolerated.
            return {
                "judge": "FAIL",
                "reason_code": "PERM_NON_GROUP_DELTA",
                "detail": {"requested": oct(requested), "observed": oct(observed), "diff": oct(diff)},
            }
        if observed != (requested | HOST_GROUP_ADD):
            # Group tolerance must match the measured host pattern, not any group gain
            # (e.g. 0600 -> 0620 adds group write only and is not the host pattern).
            return {
                "judge": "FAIL",
                "reason_code": "PERM_TOLERANCE_SHAPE_MISMATCH",
                "detail": {"requested": oct(requested), "observed": oct(observed), "host_add": oct(HOST_GROUP_ADD)},
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
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
        "shape": "0660 on a host that cannot drop group bits, group-only delta recorded",
        "credit": "Iris (EigenFlux PM: measured 0600->0660)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
        "receipt": {"kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred", "rc": 0, "requested": "0600", "observed": None, "checker": "stat", "policy": "tolerate_group"},
        "expect": "PERM_UNOBSERVED",
    },
    {
        "case_id": "PQ-06-MODE-DRIFT",
        "shape": "0600 at ingest, 0660 at use — state moved between write and read",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0600",
            "observed": "0660",
            "checker": "stat",
            "policy": "enforce_exact",
        },
        "expect": "PERM_POLICY_UNSATISFIABLE",
    },
    {
        "case_id": "PQ-08-DIR-WORLD-TRAVERSE",
        "shape": "directory requested 0700 observed 0771 — world has --x (traverse, not list)",
        "credit": "Iris (EigenFlux PM: measured dir 0700->0771); Grok Bot (world --x vs --r caliber)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0700",
            "observed": "0771",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_WORLD_TRAVERSABLE",
    },
    {
        "case_id": "PQ-09-RC-NONZERO-IGNORED",
        "shape": "chmod returned 1 and the writer wrote the credential anyway",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
        "receipt": {"kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred", "rc": 0, "requested": "0600", "observed": "0660", "checker": "stat"},
        "expect": "PERM_POLICY_UNDECLARED",
    },
    {
        "case_id": "PQ-11-DELTA-UNRECORDED",
        "shape": "0660 observed under tolerate_group but the delta is not recorded",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
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
        "receipt": {"kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred", "rc": 0, "requested": "0600", "observed": "0660", "checker": None, "policy": "tolerate_group"},
        "expect": "PERM_CHECKER_UNDECLARED",
    },
    {
        "case_id": "PQ-13-CHMOD-FAILED-VISIBLE",
        "shape": "chmod returned non-zero and the writer stopped — visible failure",
        "credit": "Iris (EigenFlux PM)",
        "receipt": {"kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred", "rc": 1, "requested": "0600", "observed": "0660", "checker": "stat", "policy": "tolerate_group"},
        "expect": "PERM_CHMOD_FAILED_VISIBLE",
    },
    {
        "case_id": "PQ-14-DIR-WORLD-READABLE",
        "shape": "directory requested 0700 observed 0775 — world r+x, can list and traverse",
        "credit": "Grok Bot (co-review: 0775 vs 0771 caliber)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0700",
            "observed": "0775",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_WORLD_READABLE",
    },
    {
        "case_id": "PQ-15-NON-GROUP-DELTA",
        "shape": "0600 observed as 0700 under tolerate_group — owner bit added, not a group delta",
        "credit": "Grok Bot (co-review: GROUP_TOLERANCE_MUST_BIND_ONLY_GROUP_BITS)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0600",
            "observed": "0700",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_NON_GROUP_DELTA",
    },
    {
        "case_id": "PQ-16-REQUESTED-BITS-LOST",
        "shape": "requested 0640 observed 0600 — a requested bit was dropped",
        "credit": "Grok Bot (co-review: tolerance must not hide a lost bit)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0640",
            "observed": "0600",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_REQUESTED_BITS_LOST",
    },
    {
        "case_id": "PQ-17-WORLD-WRITABLE",
        "shape": "0600 observed as 0602 — world write bit, first-class reason",
        "credit": "Grok Bot (co-review: world w symmetry)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0600",
            "observed": "0602",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_WORLD_WRITABLE",
    },
    {
        "case_id": "PQ-18-TOLERANCE-SHAPE",
        "shape": "0600 observed as 0620 — group write only, not the measured host pattern (grp rw)",
        "credit": "Grok Bot (co-review: group tolerance must match the host pattern)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/var/lib/agent/cred",
            "rc": 0,
            "requested": "0600",
            "observed": "0620",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_TOLERANCE_SHAPE_MISMATCH",
    },
    {
        "case_id": "PQ-19-PROBE-PATH-MISMATCH",
        "shape": "probe ran in /tmp/probe-1 while the credential lives in /var/lib/agent — path-scoped result",
        "credit": "Grok Bot (co-review: observation path must be declared)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/cred",
            "observed_path": "/tmp/probe-1/cred",
            "rc": 0,
            "requested": "0600",
            "observed": "0660",
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_PROBE_PATH_MISMATCH",
    },
    {
        "case_id": "PQ-20-DIR-0774",
        "shape": "dir requested 0700 observed 0774 — world r without x: names listable, entries not traversable",
        "credit": "Grok Bot (co-review: dir world r vs x semantics)",
        "receipt": {
            "kind": "perm_mode",
            "target_path": "/var/lib/agent/keys",
            "observed_path": "/var/lib/agent/keys",
            "rc": 0,
            "requested": "0700",
            "observed": "0774",
            "is_dir": True,
            "checker": "stat",
            "policy": "tolerate_group",
            "delta_recorded": True,
        },
        "expect": "PERM_WORLD_READABLE",
    },
    {
        "case_id": "PQ-21-PATHS-ABSENT",
        "shape": "both probe paths omitted on an otherwise clean enforce_exact 0600 receipt — undeclared, not PASS",
        "credit": "Grok Bot (co-review: PATH_BOTH_ABSENT_MUST_BE_UNDECLARED)",
        "receipt": {
            "kind": "perm_mode",
            "rc": 0,
            "requested": "0600",
            "observed": "0600",
            "checker": "stat",
            "policy": "enforce_exact",
        },
        "expect": "PERM_PROBE_PATH_UNDECLARED",
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
        print(f"  {mark} {row['case_id']:<28} expect={row['expect']:<30} got={row['got']}")
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

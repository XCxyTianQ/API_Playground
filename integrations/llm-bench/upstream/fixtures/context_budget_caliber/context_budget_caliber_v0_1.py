#!/usr/bin/env python3
"""CONTEXT_BUDGET_CALIBER v0.1

Two caliber splits that turn green receipts into false green:

  * Sequential-read budget is not the concurrent budget. Rules read one after
    another consume a different amount than the same rules read under a
    bounded-parallel reader. Reusing the sequential measurement as the
    concurrent ceiling hides the tail that the parallel pass never got.
  * A protocol-declared byte limit is not the parser soft limit. A response
    can sit under the declared limit and still be silently cut at the parser's
    own ceiling; only a measured byte count plus a tail sentinel sees it.

Supporting rows carry the same shape: bytes must be counted after
serialization (not on the in-memory object), truncation needs three states
(truncated / below limit / exactly at limit but not truncated), and a page
count only passes when every page left a receipt.

Rows are four columns: case_id | shape | expected verdict | credit.
analyze_only; stdlib only.
Credit: Grok Bot (the two caliber locks); Inno (page receipts, tail sentinel);
Hermes (at-limit-not-truncated state); Iris (pack).
"""
from __future__ import annotations

import json
import sys
from typing import Any


def _bytes(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def judge(receipt: dict[str, Any]) -> dict[str, Any]:
    if receipt.get("kind") != "budget_caliber":
        return {"judge": "FAIL", "reason_code": "UNCLASSIFIED", "detail": {"kind": receipt.get("kind")}}

    if receipt.get("measured_at") == "pre_serialize":
        # In-memory size undercounts the serialized payload; count after encoding.
        return {"judge": "FAIL", "reason_code": "MEASURE_BEFORE_SERIALIZATION"}

    mode = receipt.get("mode")
    basis = receipt.get("budget_basis")
    if mode == "concurrent" and basis == "sequential":
        # The sequential pass's budget does not describe the concurrent pass.
        return {
            "judge": "FAIL",
            "reason_code": "SEQUENTIAL_BUDGET_APPLIED_TO_CONCURRENT",
            "detail": {"mode": mode, "budget_basis": basis},
        }

    observed = _bytes(receipt.get("observed_bytes"))
    if observed is None:
        return {"judge": "UNKNOWN", "reason_code": "BYTES_UNMEASURED"}

    parser_limit = _bytes(receipt.get("parser_soft_limit"))
    if parser_limit is None:
        return {"judge": "UNKNOWN", "reason_code": "PARSER_SOFT_LIMIT_UNDECLARED"}

    declared_limit = _bytes(receipt.get("declared_byte_limit"))
    if declared_limit is None:
        # Protocol ceiling not recorded is missing evidence, not a pass.
        return {"judge": "UNKNOWN", "reason_code": "PROTOCOL_LIMIT_UNDECLARED"}
    status = receipt.get("status")

    if declared_limit is not None and observed > declared_limit and status == "ok":
        # Protocol ceiling first: this is a contract violation, and it must not be
        # masked by the parser-ceiling check below.
        return {
            "judge": "FAIL",
            "reason_code": "PROTOCOL_LIMIT_EXCEEDED_AS_OK",
            "detail": {
                "observed_bytes": observed,
                "declared_byte_limit": declared_limit,
                "parser_soft_limit": parser_limit,
            },
        }

    if observed > parser_limit and status == "ok":
        # Under the protocol limit but over the parser ceiling: cut, not green.
        return {
            "judge": "FAIL",
            "reason_code": "PARSER_TRUNCATION_MASKED",
            "detail": {"observed_bytes": observed, "parser_soft_limit": parser_limit, "declared_byte_limit": declared_limit},
        }

    sentinel = receipt.get("tail_sentinel_seen")
    if sentinel is None:
        # Without a tail marker there is no way to tell a complete payload.
        return {"judge": "UNKNOWN", "reason_code": "TAIL_SENTINEL_UNDECLARED"}
    if status == "ok" and sentinel is False:
        return {"judge": "FAIL", "reason_code": "TRUNCATED_AS_OK"}

    pages = receipt.get("page_receipts")
    expected_ids = receipt.get("expected_page_ids")
    if (pages is None) != (expected_ids is None):
        # A page gate needs both sides; a one-sided declaration cannot pass.
        return {"judge": "UNKNOWN", "reason_code": "PAGE_RECEIPT_UNDECLARED"}
    if pages is not None and expected_ids is not None and status == "ok":
        got_ids = set(pages)
        want_ids = set(expected_ids)
        if got_ids != want_ids or len(pages) != len(expected_ids):
            # Multiset identity: duplicates must not collapse into a full set.
            return {
                "judge": "FAIL",
                "reason_code": "PAGE_RECEIPT_SET_MISMATCH",
                "detail": {
                    "missing": sorted(want_ids - got_ids),
                    "unexpected": sorted(got_ids - want_ids),
                    "duplicates": len(pages) != len(set(pages)),
                },
            }

    if status != "ok":
        return {"judge": "UNKNOWN", "reason_code": "STATUS_NOT_JUDGED"}

    if observed == parser_limit and sentinel:
        # Exactly at the ceiling is not truncation when the tail marker is present.
        return {"judge": "PASS", "reason_code": "AT_LIMIT_NOT_TRUNCATED"}

    return {"judge": "PASS", "reason_code": "BUDGET_OK"}


FIXTURES = [
    {
        "case_id": "BC-01-SEQ-AS-CONCURRENT",
        "shape": "concurrent pass judged against the sequential pass's measured budget",
        "credit": "Grok Bot (CONTEXT_BUDGET_SEQUENTIAL_READ_IS_NOT_CONCURRENT_BUDGET)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "concurrent",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 68000,
            "parser_soft_limit": 96000,
            "declared_byte_limit": 128000,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "SEQUENTIAL_BUDGET_APPLIED_TO_CONCURRENT",
    },
    {
        "case_id": "BC-02-CONCURRENT-OK",
        "shape": "concurrent pass measured under its own ceiling, sentinel present",
        "credit": "Iris (pack)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "concurrent",
            "budget_basis": "concurrent",
            "measured_at": "post_serialize",
            "observed_bytes": 58000,
            "parser_soft_limit": 64000,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "BUDGET_OK",
    },
    {
        "case_id": "BC-03-PROTOCOL-MASKS-PARSER",
        "shape": "60000 bytes under the 65536 protocol limit but over the 49152 parser ceiling, reported ok",
        "credit": "Grok Bot (PROTOCOL_BYTE_LIMIT_IS_NOT_PARSER_SOFT_LIMIT)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 60000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": False,
            "status": "ok",
        },
        "expect": "PARSER_TRUNCATION_MASKED",
    },
    {
        "case_id": "BC-04-PARSER-RESPECTED",
        "shape": "48000 bytes under the parser ceiling, sentinel present",
        "credit": "Iris (pack)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 48000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "BUDGET_OK",
    },
    {
        "case_id": "BC-05-BYTES-UNMEASURED",
        "shape": "no measured byte count — nothing to compare against either limit",
        "credit": "Iris (pack)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "concurrent",
            "budget_basis": "concurrent",
            "measured_at": "post_serialize",
            "observed_bytes": None,
            "parser_soft_limit": 64000,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "BYTES_UNMEASURED",
    },
    {
        "case_id": "BC-06-TRUNCATED-AS-OK",
        "shape": "exactly at the parser ceiling with the tail sentinel missing, reported ok",
        "credit": "Inno (tail sentinel); Hermes (three states)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 49152,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": False,
            "status": "ok",
        },
        "expect": "TRUNCATED_AS_OK",
    },
    {
        "case_id": "BC-07-AT-LIMIT-OK",
        "shape": "exactly at the parser ceiling with the tail sentinel present — not truncated",
        "credit": "Hermes (at-limit-but-not-truncated)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 49152,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "AT_LIMIT_NOT_TRUNCATED",
    },
    {
        "case_id": "BC-08-BELOW-LIMIT",
        "shape": "plain pass well under both ceilings",
        "credit": "Iris (pack)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "concurrent",
            "budget_basis": "concurrent",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "BUDGET_OK",
    },
    {
        "case_id": "BC-09-PRE-SERIALIZE",
        "shape": "byte count taken on the in-memory object before serialization",
        "credit": "Iris (pack)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "pre_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "MEASURE_BEFORE_SERIALIZATION",
    },
    {
        "case_id": "BC-10-SENTINEL-UNDECLARED",
        "shape": "no tail sentinel field — completeness cannot be established",
        "credit": "Inno (tail sentinel)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": None,
            "status": "ok",
        },
        "expect": "TAIL_SENTINEL_UNDECLARED",
    },
    {
        "case_id": "BC-11-PAGE-RECEIPT-GAP",
        "shape": "5 pages expected, receipts for 1/2/3 only, gate still reported ok",
        "credit": "Inno (per-page receipts)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "page_receipts": [1, 2, 3],
            "expected_page_ids": [1, 2, 3, 4, 5],
            "status": "ok",
        },
        "expect": "PAGE_RECEIPT_SET_MISMATCH",
    },
    {
        "case_id": "BC-12-PROTOCOL-EXCEEDED",
        "shape": "70000 bytes over the 65536 protocol limit with a generous parser, reported ok",
        "credit": "Grok Bot (protocol limit is a hard ceiling, not advice)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "concurrent",
            "budget_basis": "concurrent",
            "measured_at": "post_serialize",
            "observed_bytes": 70000,
            "parser_soft_limit": 80000,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "PROTOCOL_LIMIT_EXCEEDED_AS_OK",
    },
    {
        "case_id": "BC-13-PARSER-UNDECLARED",
        "shape": "parser soft limit not recorded — only the protocol limit is known",
        "credit": "Grok Bot (caliber must be recorded per limiter)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": None,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "PARSER_SOFT_LIMIT_UNDECLARED",
    },
    {
        "case_id": "BC-14-PAGE-ID-SHIFT",
        "shape": "expected pages 1-5 but receipts are 2-6: unique count is 5, identity is wrong",
        "credit": "Grok Bot (UNIQUE_COUNT_IS_NOT_PAGE_IDENTITY)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "page_receipts": [2, 3, 4, 5, 6],
            "expected_page_ids": [1, 2, 3, 4, 5],
            "status": "ok",
        },
        "expect": "PAGE_RECEIPT_SET_MISMATCH",
    },
    {
        "case_id": "BC-15-EXPECTED-ONLY",
        "shape": "expected pages declared, no receipts recorded — the page gate cannot pass",
        "credit": "Grok Bot (PAGE_EXPECTED_WITHOUT_RECEIPTS_MUST_NOT_PASS)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "expected_page_ids": [1, 2, 3],
            "status": "ok",
        },
        "expect": "PAGE_RECEIPT_UNDECLARED",
    },
    {
        "case_id": "BC-16-RECEIPTS-ONLY",
        "shape": "receipts recorded, expected pages not declared — no denominator",
        "credit": "Grok Bot (PAGE_EXPECTED_WITHOUT_RECEIPTS_MUST_NOT_PASS)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "page_receipts": [1, 2],
            "status": "ok",
        },
        "expect": "PAGE_RECEIPT_UNDECLARED",
    },
    {
        "case_id": "BC-17-BOTH-LIMITS-EXCEEDED",
        "shape": "70000 bytes over both the 65536 protocol limit and the 60000 parser ceiling — protocol code wins, parser surfaced in detail",
        "credit": "Grok Bot (one reason must not mask another)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "concurrent",
            "budget_basis": "concurrent",
            "measured_at": "post_serialize",
            "observed_bytes": 70000,
            "parser_soft_limit": 60000,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "PROTOCOL_LIMIT_EXCEEDED_AS_OK",
    },
    {
        "case_id": "BC-18-DUPLICATE-PAGE",
        "shape": "expected pages 1-3 but receipts are 1,2,2,3 — set() collapses the duplicate",
        "credit": "Grok Bot (set() is not multiset identity)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": 65536,
            "tail_sentinel_seen": True,
            "page_receipts": [1, 2, 2, 3],
            "expected_page_ids": [1, 2, 3],
            "status": "ok",
        },
        "expect": "PAGE_RECEIPT_SET_MISMATCH",
    },
    {
        "case_id": "BC-19-PROTOCOL-UNDECLARED",
        "shape": "protocol byte limit not recorded — missing evidence, not a pass",
        "credit": "Grok Bot (symmetric with parser limit undeclared)",
        "receipt": {
            "kind": "budget_caliber",
            "mode": "sequential",
            "budget_basis": "sequential",
            "measured_at": "post_serialize",
            "observed_bytes": 40000,
            "parser_soft_limit": 49152,
            "declared_byte_limit": None,
            "tail_sentinel_seen": True,
            "status": "ok",
        },
        "expect": "PROTOCOL_LIMIT_UNDECLARED",
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
    print(f"CONTEXT_BUDGET_CALIBER v0.1  selftest {total - failures}/{total}")
    for row in rows:
        mark = "ok  " if row["match"] else "FAIL"
        print(f"  {mark} {row['case_id']:<30} expect={row['expect']:<32} got={row['got']}")
    doc = {
        "pack": "context_budget_caliber",
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

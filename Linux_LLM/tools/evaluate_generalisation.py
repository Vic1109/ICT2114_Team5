#!/usr/bin/env python3
"""Measure generic CTI extraction and IOC matching on the held-out gold set.

This script does not require PostgreSQL. Retrieval signals that need a live
index are reported as N/A unless --with-db is supplied later.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
sys.path.insert(0, str(CONFIG_DIR))

from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from ioc_normalizer import IOCNormalizer  # noqa: E402


GOLD_PATH = Path(__file__).resolve().parent / "eval_fixtures" / "generalisation" / "gold.json"

IOC_ARTIFACT_KEY = {
    "ips": "ips",
    "ipv4": "ips",
    "ipv6": "ipv6",
    "domains": "domains",
    "urls": "urls",
    "emails": "emails",
    "hashes": "hashes",
    "md5": "hashes",
    "sha1": "hashes",
    "sha256": "hashes",
    "sha512": "hashes",
    "cves": "cves",
    "cwes": "cwes",
}

IOC_NORMALIZER_TYPE = {
    "ips": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "domains": "domain",
    "urls": "url",
    "emails": "email",
    "hashes": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "cves": "cve",
    "cwes": "cwe",
}


def _norm(values):
    return {str(value).strip().upper() for value in values or [] if str(value).strip()}


def _prf(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return precision, recall, f1


def _compact_hash(value: str) -> str:
    return re.sub(r"[^a-f0-9]", "", str(value or "").lower())


def _filter_got(values, key):
    got = {str(value).lower() for value in values or []}
    if key == "ipv4":
        return {value for value in got if ":" not in value}
    if key == "ipv6":
        return {value for value in got if ":" in value}
    lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
    if key in lengths:
        return {value for value in got if len(_compact_hash(value)) == lengths[key]}
    return got


def _alert_items(alert_iocs):
    for key, values in (alert_iocs or {}).items():
        for value in values or []:
            yield key, value


def _document_matches(document, alert_iocs, lexical=False):
    text = document.get("text") or ""
    artefacts = CTIArtifactExtractor.extract(text)
    for key, value in _alert_items(alert_iocs):
        ioc_type = IOC_NORMALIZER_TYPE.get(key, key)
        canonical = IOCNormalizer.canonical(value, ioc_type) or str(value).lower()
        if lexical:
            if IOCNormalizer.lexical_contains(text, value, ioc_type):
                return True
            continue
        artifact_key = IOC_ARTIFACT_KEY.get(key, key)
        got = _filter_got(artefacts.get(artifact_key) or artefacts.get("ips") or [], key)
        if canonical.lower() in got:
            return True
        if IOCNormalizer.boundary_contains(text, value, ioc_type):
            return True
    return False


def main() -> int:
    gold = json.loads(GOLD_PATH.read_text(encoding="utf-8"))
    entity_tp = entity_fp = entity_fn = 0
    ioc_counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    rel_tp = rel_fp = rel_fn = 0
    provenance = 0
    provenance_total = 0
    polarity_ok = 0
    polarity_total = 0
    extract_started = time.perf_counter()

    for document in gold.get("documents") or []:
        text = document.get("text") or ""
        artefacts = CTIArtifactExtractor.extract(text)
        for key, expected in (document.get("entities") or {}).items():
            got = _norm(artefacts.get(key))
            want = _norm(expected)
            entity_tp += len(got & want)
            entity_fp += len(got - want)
            entity_fn += len(want - got)
        for key, expected in (document.get("iocs") or {}).items():
            artifact_key = IOC_ARTIFACT_KEY.get(key, key)
            raw_got = artefacts.get(artifact_key) or []
            if key in {"ipv4", "ipv6"} and not raw_got:
                raw_got = artefacts.get("ips") or []
            got = _filter_got(raw_got, key)
            want = {str(value).lower() for value in expected or []}
            ioc_counts[key]["tp"] += len(got & want)
            ioc_counts[key]["fp"] += len(got - want)
            ioc_counts[key]["fn"] += len(want - got)
        records = CTIArtifactExtractor.extract_relationship_records(text, artefacts)
        expected_rels = document.get("relationships") or []
        got_rels = {
            (row.get("subject", "").upper(), row.get("predicate"), row.get("object", "").upper())
            for row in records
        }
        want_rels = {
            (row.get("subject", "").upper(), row.get("predicate"), row.get("object", "").upper())
            for row in expected_rels
        }
        rel_tp += len(got_rels & want_rels)
        rel_fp += len(got_rels - want_rels)
        rel_fn += len(want_rels - got_rels)
        for row in expected_rels:
            polarity_total += 1
            if any(
                rec.get("subject", "").upper() == row.get("subject", "").upper()
                and rec.get("object", "").upper() == row.get("object", "").upper()
                and rec.get("polarity") == row.get("polarity", "explicit")
                for rec in records
            ):
                polarity_ok += 1
        ioc_records = CTIArtifactExtractor.extract_ioc_records(text)
        for row in ioc_records:
            provenance_total += 1
            if row.get("canonical_value") and row.get("context") is not None:
                provenance += 1

    extract_ms = round((time.perf_counter() - extract_started) * 1000, 2)

    signal_counts = {
        "exact": {"ok": 0, "total": 0},
        "lexical": {"ok": 0, "total": 0},
        "hybrid": {"ok": 0, "total": 0},
        "exact-negative": {"ok": 0, "total": 0},
    }
    for case in gold.get("retrieval") or []:
        signal = case.get("signal") or "exact"
        signal_counts.setdefault(signal, {"ok": 0, "total": 0})
        signal_counts[signal]["total"] += 1
        if signal == "exact-negative":
            haystack = case.get("haystack") or ""
            needle = next(iter((case.get("alert_iocs") or {}).values()), [None])[0]
            ioc_type_key = next(iter(case.get("alert_iocs") or {"ips": []}))
            ioc_type = IOC_NORMALIZER_TYPE.get(ioc_type_key, "ip")
            if not IOCNormalizer.boundary_contains(haystack, needle, ioc_type):
                signal_counts[signal]["ok"] += 1
            continue
        expected_ids = set(case.get("expected_documents") or [])
        non_matching = set(case.get("non_matching") or [])
        matched = {
            document["id"]
            for document in gold.get("documents") or []
            if _document_matches(document, case.get("alert_iocs") or {}, lexical=signal == "lexical")
        }
        ok = expected_ids <= matched and not (matched & non_matching)
        if ok:
            signal_counts[signal]["ok"] += 1

    match_started = time.perf_counter()
    haystack = " ".join(doc.get("text") or "" for doc in gold.get("documents") or [])
    for _ in range(1500):
        IOCNormalizer.boundary_contains(haystack, "203.0.113.42", "ip")
        IOCNormalizer.boundary_contains(haystack, "callback-unseen.example", "domain")
    match_ms = round((time.perf_counter() - match_started) * 1000, 2)

    entity_p, entity_r, entity_f1 = _prf(entity_tp, entity_fp, entity_fn)
    rel_p, rel_r, rel_f1 = _prf(rel_tp, rel_fp, rel_fn)

    def _rate(bucket):
        total = bucket["total"]
        return (bucket["ok"] / total) if total else None

    report = {
        "gold": str(GOLD_PATH),
        "entities": {
            "precision": entity_p,
            "recall": entity_r,
            "f1": entity_f1,
            "tp": entity_tp,
            "fp": entity_fp,
            "fn": entity_fn,
        },
        "iocs": {
            key: {
                "precision": _prf(counts["tp"], counts["fp"], counts["fn"])[0],
                "recall": _prf(counts["tp"], counts["fp"], counts["fn"])[1],
                "f1": _prf(counts["tp"], counts["fp"], counts["fn"])[2],
                **counts,
            }
            for key, counts in ioc_counts.items()
        },
        "relationships": {
            "precision": rel_p,
            "recall": rel_r,
            "f1": rel_f1,
            "tp": rel_tp,
            "fp": rel_fp,
            "fn": rel_fn,
            "polarity_preservation": (polarity_ok / polarity_total) if polarity_total else None,
        },
        "provenance_coverage": (provenance / provenance_total) if provenance_total else None,
        "retrieval": {
            "exact_recall": _rate(signal_counts["exact"]),
            "lexical_recall": _rate(signal_counts["lexical"]),
            "hybrid_exact_not_buried": _rate(signal_counts["hybrid"]),
            "negative_exact_precision": _rate(signal_counts["exact-negative"]),
            "counts": signal_counts,
            "live_hybrid_retrieval": "N/A",
        },
        "latency_ms": {
            "held_out_extraction": extract_ms,
            "boundary_match_1500x": match_ms,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

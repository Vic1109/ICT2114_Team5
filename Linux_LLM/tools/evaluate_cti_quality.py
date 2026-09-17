#!/usr/bin/env python3
"""Score production CTI extraction against a labelled gold set.

This is an evaluation tool, not a production module. It uses DocumentProcessor
and CTIArtifactExtractor exactly as upload ingestion does. Metrics are only
computed on labelled values; unlabelled extras are reported as unscored.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from rag import DocumentProcessor  # noqa: E402


def _norm(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _contains(values: Iterable[Any], expected: str) -> bool:
    expected_norm = _norm(expected)
    if not expected_norm:
        return True
    for value in values or []:
        value_norm = _norm(value)
        if expected_norm == value_norm or expected_norm in value_norm or value_norm in expected_norm:
            return True
    return False


def _score_document(extracted: Dict[str, List[str]], spec: Dict[str, Any]) -> Dict[str, Any]:
    tp = fp = fn = 0
    misses: List[str] = []
    false_hits: List[str] = []
    for key, expected_values in (spec.get("must_extract") or {}).items():
        observed = extracted.get(key) or []
        for expected in expected_values:
            if _contains(observed, expected):
                tp += 1
            else:
                fn += 1
                misses.append(f"{key}:{expected}")
    for key, rejected_values in (spec.get("must_not_extract") or {}).items():
        observed = extracted.get(key) or []
        for rejected in rejected_values:
            if _contains(observed, rejected):
                fp += 1
                false_hits.append(f"{key}:{rejected}")
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "misses": misses,
        "false_hits": false_hits,
    }


def evaluate(reports_root: Path, gold_path: Path, split: str | None = None) -> Dict[str, Any]:
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    processor = DocumentProcessor(uploads_dir="/tmp/soc-cti-eval-uploads")
    documents = []
    totals = {"tp": 0, "fp": 0, "fn": 0}
    for spec in gold.get("documents") or []:
        if split and spec.get("split") != split:
            continue
        relative = spec["relative_path"]
        pdf_path = reports_root / relative
        row = {
            "relative_path": relative,
            "split": spec.get("split"),
            "exists": pdf_path.is_file(),
        }
        if not pdf_path.is_file():
            row["error"] = "missing"
            documents.append(row)
            continue
        text, metadata = processor.process_upload(
            pdf_path.read_bytes(),
            pdf_path.name,
            save_to_disk=False,
            remember_processed=False,
        )
        artefacts = metadata.get("cti_artifacts") or CTIArtifactExtractor.extract(text)
        context = CTIArtifactExtractor.for_cti_context(artefacts)
        scored_view = dict(artefacts)
        scored_view.update(context)
        for ioc_key in ("domains", "urls", "ips", "ipv6"):
            scored_view[ioc_key] = context.get(ioc_key) or []
        score = _score_document(scored_view, spec)
        for key in ("tp", "fp", "fn"):
            totals[key] += score[key]
        row.update(score)
        row["pages"] = metadata.get("pages")
        row["characters"] = len(text)
        documents.append(row)

    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) else None
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) else None
    return {
        "gold_version": gold.get("version"),
        "reports_root": str(reports_root),
        "precision": precision,
        "recall": recall,
        "tp": totals["tp"],
        "fp": totals["fp"],
        "fn": totals["fn"],
        "documents": documents,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports-root",
        default=os.getenv("CTI_REPORTS_DIR", str(Path.home() / "Desktop/CTI-Folder/CTI-HAL-main/reports")),
    )
    parser.add_argument(
        "--gold",
        default=str(Path(__file__).resolve().parent / "eval_fixtures" / "cti_extraction_gold.json"),
    )
    parser.add_argument("--split", choices=["development", "holdout"])
    args = parser.parse_args()
    result = evaluate(Path(args.reports_root).expanduser(), Path(args.gold).expanduser(), args.split)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    if any(doc.get("error") == "missing" for doc in result["documents"]):
        return 2
    if result["fn"] or result["fp"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

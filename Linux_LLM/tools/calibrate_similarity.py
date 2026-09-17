#!/usr/bin/env python3
"""Measure retrieval similarity distributions and recommend a threshold.

RAG_EVIDENCE_SIMILARITY_THRESHOLD ships with a provisional default. Its correct
value depends on the embedding model, the corpus, and the alert mix, so it has
to be measured on the deployed server rather than guessed. This script runs
real alerts against the live corpus, reports the similarity distribution of the
retrieved candidates, and recommends a threshold from those measurements.

It is read-only with respect to the corpus: it never ingests, rebuilds, or
activates anything.

Run on the Ubuntu host, e.g.:

    python3 Linux_LLM/tools/calibrate_similarity.py \
        --alerts /var/tmp/sample-alerts.json \
        --config /etc/wazuh-analyser/config.json \
        --output /var/tmp/similarity-calibration.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from config import ConfigManager  # noqa: E402
from report import AlertAnalyzer, RAGContextManager, ReportFormatter  # noqa: E402
from runtime_utils import configure_console_encoding  # noqa: E402

configure_console_encoding()


def _load_alerts(path: Path, max_bytes: int = 16 * 1024 * 1024) -> List[Dict[str, Any]]:
    if path.stat().st_size > max_bytes:
        raise ValueError("Alert input exceeds the size limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("alerts") or payload.get("hits") or [payload]
    if not isinstance(payload, list):
        raise ValueError("Alert input must be a JSON array or an object containing 'alerts'")
    return [item for item in payload if isinstance(item, dict)]


def _percentile(values: List[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def _summarise(scores: List[float]) -> Dict[str, Any]:
    if not scores:
        return {"count": 0}
    return {
        "count": len(scores),
        "min": round(min(scores), 4),
        "p25": round(_percentile(scores, 0.25), 4),
        "median": round(statistics.median(scores), 4),
        "p75": round(_percentile(scores, 0.75), 4),
        "p90": round(_percentile(scores, 0.90), 4),
        "max": round(max(scores), 4),
        "mean": round(statistics.fmean(scores), 4),
    }


def calibrate(alerts: List[Dict[str, Any]], config, top_n: int = 10) -> Dict[str, Any]:
    """Retrieve context for each alert and record similarity distributions.

    Candidates are split by whether they carry non-semantic support. Chunks
    backed by an exact IoC or a lexical hit are treated as the "relevant"
    reference population, because that support is independent of the embedding
    space; semantic-only chunks are the population the threshold must police.
    """
    rag = RAGContextManager(
        {
            "host": config.database.host,
            "port": config.database.port,
            "dbname": config.database.database,
            "user": config.database.user,
            "password": config.database.password,
        },
        rag_config=config.rag,
    )
    # Force instrumentation on and the evidence gate off, so the raw candidate
    # distribution is observed rather than the already-filtered one.
    rag.similarity_instrumentation = True
    rag.evidence_similarity_threshold = 0.0

    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = rag

    analyzer = AlertAnalyzer()
    cleaned = analyzer.clean_log_data(alerts)
    if not cleaned:
        raise ValueError("No alerts survived normalisation; nothing to calibrate against")

    supported_scores: List[float] = []
    semantic_only_scores: List[float] = []
    per_query: List[Dict[str, Any]] = []

    exact_terms = formatter._build_exact_terms_from_alerts(cleaned)
    for query in formatter._build_focused_retrieval_queries(cleaned):
        results = rag._hybrid_search(
            query,
            k=max(top_n, rag.max_retrieval_docs),
            exact_terms=exact_terms,
            enforce_diversity=False,
        )
        query_scores = []
        for item in results:
            score = item.get("semantic_score")
            if score is None:
                continue
            score = float(score)
            query_scores.append(score)
            if rag._has_non_semantic_support(item):
                supported_scores.append(score)
            else:
                semantic_only_scores.append(score)

        per_query.append({
            "query_chars": len(query),
            "results": len(results),
            "top_similarities": [round(value, 4) for value in sorted(query_scores, reverse=True)[:top_n]],
            "observation": dict(rag.last_similarity_observation),
        })

    # A threshold at the 25th percentile of independently-supported matches
    # keeps most genuinely relevant chunks while cutting the long weak tail.
    if supported_scores:
        recommended = _percentile(supported_scores, 0.25)
    elif semantic_only_scores:
        recommended = _percentile(semantic_only_scores, 0.75)
    else:
        recommended = float(config.rag.evidence_similarity_threshold)

    return {
        "alerts_analysed": len(cleaned),
        "queries": len(per_query),
        "configured_candidate_threshold": config.rag.similarity_threshold,
        "configured_evidence_threshold": config.rag.evidence_similarity_threshold,
        "exact_or_lexical_supported": _summarise(supported_scores),
        "semantic_only": _summarise(semantic_only_scores),
        "recommended_evidence_threshold": round(recommended, 3),
        "recommendation_basis": (
            "25th percentile of chunks independently supported by an exact IoC or "
            "lexical match" if supported_scores else
            "75th percentile of semantic-only chunks (no independently supported "
            "matches were observed; treat this as a weak signal and widen the "
            "alert sample)"
        ),
        "per_query": per_query,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", required=True, type=Path, help="JSON file of representative alerts")
    parser.add_argument("--config", type=Path, default=None, help="Application config file")
    parser.add_argument("--output", type=Path, default=None, help="Write the JSON report here")
    parser.add_argument("--top-n", type=int, default=10, help="Similarity scores to report per query")
    args = parser.parse_args()

    config = ConfigManager(str(args.config) if args.config else None)
    report = calibrate(_load_alerts(args.alerts), config, top_n=args.top_n)
    rendered = json.dumps(report, indent=2, default=str)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote calibration report to {args.output}")
    else:
        print(rendered)

    print(
        "\nSet RAG_EVIDENCE_SIMILARITY_THRESHOLD="
        f"{report['recommended_evidence_threshold']} after reviewing the "
        "distributions above against known-relevant and known-irrelevant results."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

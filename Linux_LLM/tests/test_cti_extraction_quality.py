#!/usr/bin/env python3
"""CTI extraction quality: entities, relationships, provenance, and PDF glue."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from report import ReportFormatter  # noqa: E402


FIN7_PROSE = """
FIN7 used the HALFBAKED backdoor to maintain persistence after a phishing LNK.
The malware family HALFBAKED connected to 198.100.119.6 over HTTP.
A sample hash is 6a5a42ed234910121dbb7d1994ab5a5e.
The campaign also dropped update.vbs and wrote HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update.
Named mutex: Global\\HalfbakedLock
User-Agent: Mozilla/5.0 (Windows NT 6.1; HALFBAKED)
IPv6 callback 2001:db8:85a3::8a2e:370:7334 was listed as C2.
"""

COZYDUKE_PROSE = """
The CozyDuke malware family, also known as CozyCar, is associated with the
threat actor APT29. Related articles: APT28 attacks NATO. Also read APT41 news.
CozyDuke exploits CVE-2015-0000 in this synthetic excerpt.
"""

GLUED_PDF = (
    "Callback http://198.100.119.6:80/cdhxxp://198.100.119.6:443/cd "
    "and word.application plus it.powershell should not become domains."
)


class EntityExtractionTests(unittest.TestCase):
    def test_malware_campaign_and_host_artefacts_are_extracted(self):
        artefacts = CTIArtifactExtractor.extract(FIN7_PROSE)
        self.assertIn("FIN7", artefacts.get("threat_actors", []))
        malware = [value.upper() for value in artefacts.get("malware_families", [])]
        self.assertTrue(any("HALFBAKED" in value for value in malware), malware)
        self.assertIn("198.100.119.6", artefacts.get("ips", []))
        self.assertIn("2001:db8:85a3::8a2e:370:7334", artefacts.get("ips", []))
        self.assertTrue(any("update.vbs" in value.lower() for value in artefacts.get("filenames", [])))
        self.assertTrue(
            any("CurrentVersion\\Run" in value for value in artefacts.get("registry_keys", []))
        )
        self.assertTrue(any("HalfbakedLock" in value for value in artefacts.get("mutexes", [])))
        self.assertTrue(artefacts.get("user_agents"))

    def test_relationships_are_chunk_local_and_evidence_backed(self):
        records = CTIArtifactExtractor.extract_relationship_records(FIN7_PROSE)
        self.assertTrue(records, "No relationships extracted from explicit actor-uses-malware prose")
        uses = [
            record for record in records
            if record.get("predicate") in {"uses", "communicates_with", "exploits"}
        ]
        self.assertTrue(uses)
        for record in uses:
            self.assertTrue(record.get("evidence"))
            self.assertIn(record["subject"].upper(), FIN7_PROSE.upper() + " HALFBAKED FIN7")
            self.assertIn(record["object"].upper()[:6], FIN7_PROSE.upper())

    def test_distant_cooccurrence_is_not_a_relationship(self):
        prose = (
            "APT29 is a threat actor. " + ("background " * 40)
            + "Unrelated operators used Maze ransomware against hospitals."
        )
        records = CTIArtifactExtractor.extract_relationship_records(prose)
        self.assertFalse(
            any(
                record.get("subject") == "APT29" and "Maze" in str(record.get("object"))
                for record in records
            ),
            records,
        )

    def test_sidebar_apt_ids_are_not_promoted_from_related_articles(self):
        artefacts = CTIArtifactExtractor.extract(COZYDUKE_PROSE)
        actors = artefacts.get("threat_actors", [])
        self.assertIn("APT29", actors)
        self.assertNotIn("APT28", actors)
        self.assertNotIn("APT41", actors)

    def test_glued_urls_split_and_false_domains_are_not_promoted(self):
        artefacts = CTIArtifactExtractor.extract(GLUED_PDF)
        context = CTIArtifactExtractor.for_cti_context(artefacts)
        urls = context.get("urls") or artefacts.get("urls") or []
        self.assertTrue(any("198.100.119.6:80" in url for url in urls), urls)
        self.assertFalse(any("cdhxxp" in url.lower() for url in urls), urls)
        domains = context.get("domains") or []
        self.assertNotIn("word.application", domains)
        self.assertNotIn("it.powershell", domains)
        artefacts = CTIArtifactExtractor.extract("C2 on port 443.host listed beside the payload.")
        context = CTIArtifactExtractor.for_cti_context(artefacts)
        self.assertNotIn("443.host", context.get("domains") or [])
        self.assertNotIn("443.host", artefacts.get("domains") or [])

    def test_pdf_glue_this_is_not_a_thai_domain(self):
        artefacts = CTIArtifactExtractor.extract(
            "Neighboring utilities.This report also mentions mazedecrypt.top and aoacugmutagkwctu.onion."
        )
        domains = artefacts.get("domains") or []
        self.assertNotIn("neighboringutilities.th", domains)
        self.assertNotIn("utilities.th", domains)
        context = CTIArtifactExtractor.for_cti_context(artefacts)
        self.assertIn("mazedecrypt.top", context.get("domains") or [])
        artefacts = CTIArtifactExtractor.extract(
            "Deep Insight into FIN7 Malware Chain From Office Macro Malware to Lightweight JS Loader"
        )
        malware = [value.upper() for value in artefacts.get("malware_families", [])]
        self.assertFalse(any(value in {"CHAIN", "INSIGHT", "LOADER", "LIGHTWEIGHT JS"} for value in malware), malware)
        artefacts = CTIArtifactExtractor.extract(
            'Aliases: "O!ICE MONKEYS") IS and NEXT-GEN IOT. Threat actor called CozyBear.'
        )
        aliases = " ".join(artefacts.get("threat_actor_aliases", []) + artefacts.get("threat_actors", []))
        self.assertNotIn("O!ICE", aliases)
        self.assertNotIn("NEXT-GEN IOT", aliases.upper())
        self.assertIn("COZYBEAR", aliases.upper())


class RelationshipRankingTests(unittest.TestCase):
    def test_chunk_local_relationship_outranks_same_document_cooccurrence(self):
        formatter = ReportFormatter.__new__(ReportFormatter)
        formatter.rag_manager = type("Rag", (), {
            "max_retrieval_docs": 8,
            "_contains_exact_term": lambda self, haystack, term: term.lower() in haystack,
            "_score_exact_candidate": lambda self, evidence, source: 1.4 if evidence else 0.0,
            "_is_high_signal_search_value": lambda self, value: True,
        })()
        alerts = [{
            "src_ip": "198.100.119.6",
            "observed_iocs": {"ips": ["198.100.119.6"], "hashes": ["6a5a42ed234910121dbb7d1994ab5a5e"]},
            "behavior_tags": ["possible_c2"],
        }]
        related = {
            "id": 1,
            "source": "custom_document",
            "content": "FIN7 uses HALFBAKED which beacons to 198.100.119.6",
            "metadata": {
                "cti_artifacts": {"ips": ["198.100.119.6"], "threat_actors": ["FIN7"], "malware_families": ["HALFBAKED"]},
                "cti_relationships": [{
                    "subject": "FIN7",
                    "predicate": "uses",
                    "object": "HALFBAKED",
                    "evidence": "FIN7 uses HALFBAKED",
                }, {
                    "subject": "HALFBAKED",
                    "predicate": "communicates_with",
                    "object": "198.100.119.6",
                    "evidence": "HALFBAKED beacons to 198.100.119.6",
                }],
                "cti_behavior_tags": ["possible_c2"],
            },
            "score": 0.4,
            "match_types": ["exact"],
            "match_evidence": ["ip matched extracted CTI artifact 198.100.119.6"],
        }
        cooccur = {
            "id": 2,
            "source": "custom_document",
            "content": "A long report also mentions FIN7, Maze ransomware, and unrelated banks.",
            "metadata": {
                "cti_artifacts": {"threat_actors": ["FIN7"], "malware_families": ["Maze"]},
                "cti_relationships": [],
                "cti_behavior_tags": ["malware_or_destructive_activity"],
            },
            "score": 0.92,
            "match_types": ["semantic"],
            "match_evidence": ["semantic similarity"],
        }
        selected = formatter._select_relevant_context_docs([cooccur, related], alerts, max_docs=2)
        self.assertEqual(selected[0]["id"], 1)
        self.assertTrue(selected[0].get("current_relationship_overlap"))


if __name__ == "__main__":
    unittest.main()

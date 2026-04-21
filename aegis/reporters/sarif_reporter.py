import json
from datetime import datetime, timezone

from aegis.core.findings import OWASPCategory, Severity, ScanResult
from aegis.reporters.base import BaseReporter
from aegis.reporters.compliance import ComplianceMapper


_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFReporter(BaseReporter):

    def generate(self, result: ScanResult, output_path: str) -> str:
        rules = self._build_rules()
        rule_index = {cat: idx for idx, cat in enumerate(OWASPCategory)}
        results = self._build_results(result, rule_index)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AEGIS",
                            "semanticVersion": "0.1.0",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/aegis-security/aegis",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.fromtimestamp(
                                result.start_time, tz=timezone.utc
                            ).isoformat(),
                            "endTimeUtc": (
                                datetime.fromtimestamp(result.end_time, tz=timezone.utc).isoformat()
                                if result.end_time
                                else datetime.now(timezone.utc).isoformat()
                            ),
                            "properties": {
                                "target": result.target,
                                "profile": result.profile,
                                "scannersRun": result.scanners_run,
                                "totalTokens": result.total_tokens,
                                "totalCostUsd": round(result.total_cost_usd, 4),
                            },
                        }
                    ],
                }
            ],
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, ensure_ascii=False)

        return output_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rules() -> list[dict]:
        """Build a SARIF rule entry for every OWASP LLM Top 10 category."""
        rules: list[dict] = []
        for cat in OWASPCategory:
            mapping = ComplianceMapper.get_mapping(cat)
            code = cat.value.split(":")[0].strip()  # e.g. "LLM01"
            name = cat.value.split(":", 1)[1].strip()  # e.g. "Prompt Injection"
            rules.append(
                {
                    "id": code,
                    "name": name,
                    "shortDescription": {"text": cat.value},
                    "fullDescription": {"text": f"OWASP LLM Top 10 - {cat.value}"},
                    "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/#{code}",
                    "properties": {
                        "tags": ["security", "llm", "owasp"],
                        "compliance": {
                            "eu_ai_act": mapping.eu_ai_act,
                            "nist_ai_rmf": mapping.nist_ai_rmf,
                            "nist_ai_600": mapping.nist_ai_600,
                            "mitre_atlas": mapping.mitre_atlas,
                        },
                    },
                }
            )
        return rules

    @staticmethod
    def _build_results(result: ScanResult, rule_index: dict[OWASPCategory, int]) -> list[dict]:
        """Convert each Finding into a SARIF result object."""
        sarif_results: list[dict] = []
        for finding in result.findings:
            code = finding.category.value.split(":")[0].strip()
            mapping = ComplianceMapper.get_mapping(finding.category)
            entry: dict = {
                "ruleId": code,
                "ruleIndex": rule_index[finding.category],
                "level": _SEVERITY_TO_LEVEL.get(finding.severity, "note"),
                "message": {
                    "text": finding.description or finding.title,
                },
                "properties": {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "technique": finding.technique,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "scannerName": finding.scanner_name,
                    "tokensUsed": finding.tokens_used,
                    "costUsd": round(finding.cost_usd, 6),
                    "compliance": {
                        "owasp": finding.category.value,
                        "eu_ai_act": mapping.eu_ai_act,
                        "nist_ai_rmf": mapping.nist_ai_rmf,
                        "nist_ai_600": mapping.nist_ai_600,
                    },
                },
            }
            # Include the target URI as a physical location if available
            if result.target:
                entry["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": result.target,
                                "description": {"text": "LLM API endpoint under test"},
                            }
                        }
                    }
                ]
            sarif_results.append(entry)
        return sarif_results

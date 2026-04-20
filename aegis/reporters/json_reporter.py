import json
from datetime import datetime, timezone

from aegis.core.findings import ScanResult, Severity
from aegis.reporters import BaseReporter
from aegis.reporters.compliance import ComplianceMapper


class JSONReporter(BaseReporter):

    def generate(self, result: ScanResult, output_path: str) -> str:
        report = {
            "aegis_version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_metadata": {
                "target": result.target,
                "profile": result.profile,
                "duration_seconds": round(result.duration_seconds, 1),
                "total_tokens": result.total_tokens,
                "total_cost_usd": round(result.total_cost_usd, 4),
                "scanners_run": result.scanners_run,
                "start_time": datetime.fromtimestamp(result.start_time, tz=timezone.utc).isoformat(),
                "end_time": (
                    datetime.fromtimestamp(result.end_time, tz=timezone.utc).isoformat()
                    if result.end_time
                    else None
                ),
            },
            "summary": {
                "total_findings": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in result.findings if f.severity == Severity.INFO),
            },
            "findings": [f.to_dict() for f in result.findings],
            "compliance_summary": ComplianceMapper.generate_compliance_summary(result.findings),
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

        return output_path

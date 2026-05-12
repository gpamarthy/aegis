import json
import uuid
import pathlib
import aiosqlite
from typing import List
from aegis.core.findings import ScanResult, Finding
from aegis.core.logger import get_logger

logger = get_logger("core.database")

DEFAULT_DB_PATH = pathlib.Path.home() / ".aegis" / "aegis.db"

class AegisDB:
    """Manages persistent state for scan results using SQLite."""

    def __init__(self, db_path: str | pathlib.Path = DEFAULT_DB_PATH):
        self.db_path = pathlib.Path(db_path)

    async def initialize(self):
        """Ensure the database and tables exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    profile TEXT,
                    total_tokens INTEGER,
                    total_cost_usd REAL,
                    duration_seconds REAL,
                    scanners_run TEXT,
                    start_time REAL,
                    end_time REAL
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    category TEXT,
                    technique TEXT,
                    payload TEXT,
                    response TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    compliance TEXT,
                    timestamp REAL,
                    scanner_name TEXT,
                    tokens_used INTEGER,
                    cost_usd REAL,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)
            await db.commit()
        logger.debug("Database initialized", path=str(self.db_path))

    async def save_scan_result(self, result: ScanResult):
        """Persist a complete ScanResult and its findings."""
        scan_id = str(uuid.uuid4())[:8]
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        result.target,
                        result.profile,
                        result.total_tokens,
                        result.total_cost_usd,
                        result.duration_seconds,
                        json.dumps(result.scanners_run),
                        result.start_time,
                        result.end_time
                    )
                )
                
                for f in result.findings:
                    compliance_data = {}
                    if f.compliance:
                        compliance_data = {
                            "owasp": f.compliance.owasp.value,
                            "eu_ai_act": f.compliance.eu_ai_act,
                            "nist_ai_rmf": f.compliance.nist_ai_rmf,
                            "nist_ai_600": f.compliance.nist_ai_600,
                            "mitre_atlas": f.compliance.mitre_atlas,
                        }

                    await db.execute(
                        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            f.id,
                            scan_id,
                            f.title,
                            f.description,
                            f.severity.value,
                            f.category.value,
                            f.technique,
                            f.payload,
                            f.response,
                            f.evidence,
                            f.remediation,
                            json.dumps(compliance_data),
                            f.timestamp,
                            f.scanner_name,
                            f.tokens_used,
                            f.cost_usd
                        )
                    )
                await db.commit()
            logger.info("Scan results persisted to database", scan_id=scan_id, findings=len(result.findings))
        except Exception as e:
            logger.error("Failed to save scan results", error=str(e))
            raise

import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from aegis.core.findings import Finding, ScanResult, Severity, OWASPCategory

# App / state
# ---------------------------------------------------------------------------

# hack: CORS allows * for dev, lock down before deploy
app = FastAPI(
    title="AEGIS Dashboard",
    description="AI Exploitation & Guardrail Inspection Suite - Web Dashboard",
    version="0.1.0",
)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# In-memory storage for scan results
_scan_results: list[ScanResult] = []

# ---
# Request / response schemas
# ==

class ScanRequest(BaseModel):
    target: str
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: str = ""
    profile: str = "quick"

class FindingOut(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    category: str
    technique: str
    payload: str
    response: str
    evidence: str
    remediation: str
    scanner_name: str
    tokens_used: int
    cost_usd: float

    class Config:
        from_attributes = True

class ScanResultOut(BaseModel):
    scan_index: int
    target: str
    profile: str
    total_findings: int
    total_tokens: int
    total_cost_usd: float
    duration_seconds: float
    scanners_run: list[str]
    findings: list[dict]
    summary: dict

    class Config:
        from_attributes = True

# ---------------------------------------------------------------------------
# Helpers

def _result_to_dict(result: ScanResult, index: int) -> dict:
    findings = [f.to_dict() for f in result.findings]
    return {
        "scan_index": index,
        "target": result.target,
        "profile": result.profile,
        "total_findings": len(result.findings),
        "total_tokens": result.total_tokens,
        "total_cost_usd": round(result.total_cost_usd, 4),
        "duration_seconds": round(result.duration_seconds, 1),
        "scanners_run": result.scanners_run,
        "findings": findings,
        "summary": result.summary,
    }

# Routes - HTML pages
# ===

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request, "dashboard.html", {"scans": _scan_results}
    )

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request, "dashboard.html", {"scans": _scan_results}
    )

# Routes - API

@app.post("/api/scan")
async def start_scan(scan_req: ScanRequest):
    """Start a new scan.

    For the web MVP this creates a mock scan result demonstrating the
    pipeline. For real scans, integrate with ``aegis.scanners.engine.run_scan``.
    """
    start = time.time()

    # Attempt a real scan if possible, otherwise create a demo result
    try:
        from aegis.core.scan_config import ScanConfig, ScanProfile, TargetConfig
        from aegis.scanners.engine import run_scan

        target_config = TargetConfig(
            endpoint=scan_req.target,
            provider=scan_req.provider,
            model=scan_req.model,
            api_key=scan_req.api_key,
        )

        profile_map = {
            "quick": ScanProfile.QUICK,
            "standard": ScanProfile.STANDARD,
            "full": ScanProfile.FULL,
            "stealth": ScanProfile.STEALTH,
        }

        scan_config = ScanConfig(
            target=target_config,
            profile=profile_map.get(scan_req.profile, ScanProfile.QUICK),
        )

        result = await run_scan(scan_config)

    except Exception as exc:
        # If the scan engine fails (e.g. no valid API key or connector
        # issues), return the error wrapped in a result so the dashboard
        # can still display something useful.
        end = time.time()
        result = ScanResult(
            target=scan_req.target,
            profile=scan_req.profile,
            duration_seconds=end - start,
            start_time=start,
            end_time=end,
            scanners_run=[],
            findings=[
                Finding(
                    title="Scan engine error",
                    description=f"The scan could not be completed: {exc}",
                    severity=Severity.INFO,
                    category=OWASPCategory.LLM01,
                    technique="n/a",
                    payload="",
                    response="",
                    scanner_name="engine",
                ),
            ],
        )

    _scan_results.append(result)
    index = len(_scan_results) - 1
    return JSONResponse(content=_result_to_dict(result, index))

@app.get("/api/scans")
async def list_scans():
    return JSONResponse(
        content=[
            _result_to_dict(r, i) for i, r in enumerate(_scan_results)
        ]
    )

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    if scan_id < 0 or scan_id >= len(_scan_results):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return JSONResponse(content=_result_to_dict(_scan_results[scan_id], scan_id))

@app.get("/api/findings/{scan_id}")
async def get_findings(scan_id: int):
    if scan_id < 0 or scan_id >= len(_scan_results):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    result = _scan_results[scan_id]
    return JSONResponse(content=[f.to_dict() for f in result.findings])

# Server entrypoint

def start_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False) -> None:
    import uvicorn
    uvicorn.run(
        "aegis.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )

if __name__ == "__main__":
    start_server()

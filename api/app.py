"""
AI Sentinel — Cloud API Service
FastAPI wrapper around the vulnerability prioritization engine.

Provides endpoints for:
- Starting background scans and tracking progress
- Retrieving vulnerability summaries by severity
- Retrieving individual finding details with category and artifact info
- Direct prioritization of pre-parsed or raw scanner results
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Imports — scanner engine + prioritizer
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")
sys.path.insert(0, SCRIPT_DIR)

# Import SentinelEngine from sentinel-scan.py (hyphenated filename)
_spec = importlib.util.spec_from_file_location(
    "sentinel_scan", os.path.join(SCRIPT_DIR, "sentinel-scan.py")
)
_sentinel_scan = importlib.util.module_from_spec(_spec)
sys.modules["sentinel_scan"] = _sentinel_scan
_spec.loader.exec_module(_sentinel_scan)
SentinelEngine = _sentinel_scan.SentinelEngine

from prioritize_vulnerabilities import (
    collect_all_findings,
    parse_fickling_safety_results,
    parse_modelscan_json,
    parse_osv_scanner_json,
    parse_picklescan_txt,
    parse_semgrep_json,
    prioritize_with_openai,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Sentinel",
    description=(
        "AI-powered vulnerability prioritization for ML model artifacts. "
        "Upload scan results from open-source tools (Fickling, ModelScan, "
        "Semgrep, OSV-Scanner, etc.) and get AI-prioritized findings."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")

# ---------------------------------------------------------------------------
# Category mapping — map scanner categories to the 5 canonical categories
# ---------------------------------------------------------------------------

CATEGORY_MAP = {
    # Secrets Exposure
    "code sast": "Secrets Exposure",
    "pipeline — broken scanner": "Configuration Risk",
    "pipeline — broken scanner (coverage gap)": "Configuration Risk",
    # Artifact Integrity Risk
    "model artifact": "Artifact Integrity Risk",
    "model artifact — pickle": "Artifact Integrity Risk",
    "model artifact — pickle deserialization": "Artifact Integrity Risk",
    "model artifact — supply chain": "Artifact Integrity Risk",
    # Dependency Risk
    "dependency cve": "Dependency Risk",
    "dependency vulnerability (cve)": "Dependency Risk",
    "dependency policy": "Dependency Risk",
    "binary cve": "Dependency Risk",
    "binary vulnerability (cve)": "Dependency Risk",
    # Provenance Issues
    "sbom": "Provenance Issues",
    "agent architecture": "Provenance Issues",
    # Configuration Risk
    "prompt regression": "Configuration Risk",
    "pipeline error": "Configuration Risk",
}

VALID_CATEGORIES = [
    "Secrets Exposure",
    "Artifact Integrity Risk",
    "Dependency Risk",
    "Provenance Issues",
    "Configuration Risk",
]


def map_category(raw_category: str) -> str:
    """Map a raw scanner category to one of the 5 canonical categories."""
    return CATEGORY_MAP.get(raw_category.lower(), "Configuration Risk")


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "WARNING": "Medium",
    "INFO": "Low",
    "INFORMATIONAL": "Low",
    "UNKNOWN": "Low",
}


def normalize_severity(raw: str) -> str:
    """Normalize severity to one of: Critical, High, Medium, Low."""
    return SEVERITY_MAP.get(raw.upper(), "Low")


# ---------------------------------------------------------------------------
# In-memory scan state store
# ---------------------------------------------------------------------------

_scans: dict[str, dict] = {}
_scans_lock = threading.Lock()


def _run_scan_background(scan_id: str, target_dir: str, config_dir: str | None, prioritize: bool, model: str):
    """Execute a scan in a background thread, updating progress as scanners complete."""
    try:
        engine = SentinelEngine(target_dir, config_dir)
        total_scanners = len(engine.scanners)

        with _scans_lock:
            _scans[scan_id]["status"] = "running"
            _scans[scan_id]["total_scanners"] = total_scanners

        ts = datetime.now(timezone.utc)
        all_findings = []
        tool_results = {}

        for idx, scanner in enumerate(engine.scanners):
            with _scans_lock:
                _scans[scan_id]["current_scanner"] = scanner.name
                _scans[scan_id]["scanners_completed"] = idx
                _scans[scan_id]["progress_percent"] = round((idx / total_scanners) * 100)

            try:
                findings = scanner.scan(engine.target_dir, engine.config_dir)
                tool_results[scanner.name] = {
                    "installed": len([f for f in findings if "Missing" in f.title or "Not Found" in f.title]) == 0,
                    "count": len([f for f in findings if "Missing" not in f.title and "Not Found" not in f.title]),
                }
                actual = [f for f in findings if "Missing" not in f.title and "Not Found" not in f.title]
                all_findings.extend(actual)
            except Exception:
                tool_results[scanner.name] = {"installed": False, "count": 0}

        elapsed = (datetime.now(timezone.utc) - ts).total_seconds()

        # Deduplicate
        unique_findings = []
        seen = set()
        for f in all_findings:
            if f._hash not in seen:
                seen.add(f._hash)
                unique_findings.append(f.to_dict())

        results = {
            "metadata": {
                "duration_seconds": elapsed,
                "total_findings": len(unique_findings),
                "tool_results": tool_results,
            },
            "findings": unique_findings,
        }

        # AI prioritization
        if prioritize and OPENAI_API_KEY and unique_findings:
            try:
                prioritized = prioritize_with_openai(unique_findings, model=model, api_key=OPENAI_API_KEY)
                results["prioritized"] = prioritized
            except Exception:
                pass

        with _scans_lock:
            _scans[scan_id]["status"] = "completed"
            _scans[scan_id]["progress_percent"] = 100
            _scans[scan_id]["scanners_completed"] = total_scanners
            _scans[scan_id]["current_scanner"] = None
            _scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _scans[scan_id]["results"] = results

    except Exception as e:
        with _scans_lock:
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = str(e)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    scanner: str = ""
    scanner_severity: str = ""
    title: str = ""
    description: str = ""
    category: str = ""
    file: Optional[str] = None
    line: Optional[int] = None
    indicators: dict = Field(default_factory=dict)


class PrioritizeRequest(BaseModel):
    findings: list[Finding] = Field(
        ..., description="Array of vulnerability findings from scanners"
    )
    model: str = Field(default="gpt-4o", description="OpenAI model to use")


class ScanResultsRequest(BaseModel):
    scanner: str = Field(
        ..., description="Scanner name: fickling, semgrep, modelscan, picklescan, osv-scanner"
    )
    results: dict | list | str = Field(
        ..., description="Raw scanner output (JSON object/array or text)"
    )
    model: str = Field(default="gpt-4o", description="OpenAI model to use")


class StartScanRequest(BaseModel):
    target_dir: str = Field(default=".", description="Directory to scan")
    config_dir: Optional[str] = Field(default=None, description="Configs directory")
    prioritize: bool = Field(default=False, description="Run AI prioritization after scan")
    model: str = Field(default="gpt-4o", description="OpenAI model for prioritization")


class ScanIdRequest(BaseModel):
    scan_id: str = Field(..., description="The scan identifier returned by POST /api/v1/scan")


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    openai_configured: bool


# ---------------------------------------------------------------------------
# Endpoints — Scan lifecycle
# ---------------------------------------------------------------------------


@app.post("/api/v1/scan")
async def start_scan(request: StartScanRequest):
    """
    Start a new background security scan.

    Returns a scan_id that can be used to poll progress, retrieve the
    vulnerability summary, and fetch individual findings.
    """
    scan_id = str(uuid.uuid4())

    with _scans_lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "status": "queued",
            "progress_percent": 0,
            "total_scanners": 0,
            "scanners_completed": 0,
            "current_scanner": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "target_dir": request.target_dir,
            "results": None,
            "error": None,
        }

    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, request.target_dir, request.config_dir, request.prioritize, request.model),
        daemon=True,
    )
    thread.start()

    return {"scan_id": scan_id, "status": "queued", "message": "Scan started"}


@app.post("/api/v1/scan/progress")
async def get_scan_progress(request: ScanIdRequest):
    """
    Get the current progress of a scan as a percentage (0-100).

    Returns the overall progress, which scanner is currently running,
    and how many scanners have completed out of the total.
    """
    with _scans_lock:
        scan = _scans.get(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": request.scan_id,
        "status": scan["status"],
        "progress_percent": scan["progress_percent"],
        "scanners_completed": scan["scanners_completed"],
        "total_scanners": scan["total_scanners"],
        "current_scanner": scan["current_scanner"],
    }


@app.post("/api/v1/scan/summary")
async def get_scan_summary(request: ScanIdRequest):
    """
    Get the vulnerability count summary, categorized by severity.

    Returns counts for Critical, High, Medium, and Low severities.
    Only available once the scan has completed.
    """
    with _scans_lock:
        scan = _scans.get(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "completed":
        return {
            "scan_id": request.scan_id,
            "status": scan["status"],
            "message": "Scan has not completed yet. Poll /progress to check status.",
            "severity_counts": None,
            "total_vulnerabilities": None,
        }

    results = scan["results"]
    findings = results.get("findings", [])

    # If prioritized results exist, use AI severity; otherwise use scanner severity
    prioritized = results.get("prioritized", {}).get("prioritized_vulnerabilities", [])
    if prioritized:
        source = prioritized
        severity_key = "ai_severity"
    else:
        source = findings
        severity_key = "scanner_severity"

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in source:
        sev = normalize_severity(f.get(severity_key, f.get("scanner_severity", "LOW")))
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "scan_id": request.scan_id,
        "status": "completed",
        "total_vulnerabilities": sum(counts.values()),
        "severity_counts": counts,
    }


@app.post("/api/v1/scan/findings")
async def get_scan_findings(request: ScanIdRequest):
    """
    Get all findings from a completed scan.

    Each finding includes:
    - metadata: description of what the finding is
    - category: one of Secrets Exposure, Artifact Integrity Risk,
                Dependency Risk, Provenance Issues, Configuration Risk
    - artifact: the specific file where the vulnerability was found
    - severity: normalized to Critical, High, Medium, Low
    """
    with _scans_lock:
        scan = _scans.get(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "completed":
        return {
            "scan_id": request.scan_id,
            "status": scan["status"],
            "message": "Scan has not completed yet. Poll /progress to check status.",
            "findings": None,
        }

    results = scan["results"]
    raw_findings = results.get("findings", [])

    # Merge AI prioritization data if available
    prioritized = results.get("prioritized", {}).get("prioritized_vulnerabilities", [])
    ai_map = {}
    for p in prioritized:
        fid = p.get("id", "")
        if fid:
            ai_map[fid] = p

    output_findings = []
    for f in raw_findings:
        fid = f.get("_hash", "")
        ai = ai_map.get(fid, {})

        severity_raw = ai.get("ai_severity", f.get("scanner_severity", "LOW"))
        severity = normalize_severity(severity_raw)
        category = map_category(f.get("category", ""))

        entry = {
            "id": fid,
            "severity": severity,
            "category": category,
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "artifact": f.get("file", None),
            "scanner": f.get("scanner", ""),
            "line": f.get("line", None),
            "indicators": f.get("indicators", {}),
        }

        # Include AI enrichment if available
        if ai:
            entry["priority_rank"] = ai.get("priority_rank")
            entry["cvss_estimate"] = ai.get("cvss_estimate")
            entry["exploit_likelihood"] = ai.get("exploit_likelihood")
            entry["blast_radius"] = ai.get("blast_radius")
            entry["attack_vector"] = ai.get("attack_vector")
            entry["remediation"] = ai.get("remediation")
            entry["justification"] = ai.get("justification")

        output_findings.append(entry)

    return {
        "scan_id": request.scan_id,
        "status": "completed",
        "total_findings": len(output_findings),
        "findings": output_findings,
    }


@app.post("/api/v1/scans")
async def list_scans():
    """
    List all scans with their current status and progress.
    """
    with _scans_lock:
        summaries = []
        for sid, scan in _scans.items():
            summaries.append({
                "scan_id": sid,
                "status": scan["status"],
                "progress_percent": scan["progress_percent"],
                "target_dir": scan["target_dir"],
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"],
            })
    return {"scans": summaries}


# ---------------------------------------------------------------------------
# Endpoints — Existing (health, prioritize, scan-results, upload)
# ---------------------------------------------------------------------------


@app.get("/api/v1/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        openai_configured=bool(OPENAI_API_KEY),
    )


@app.post("/api/v1/prioritize")
async def prioritize(request: PrioritizeRequest):
    """
    Accept pre-parsed findings and prioritize them with AI.

    Send an array of findings (from any scanner) and get back
    AI-prioritized vulnerabilities ranked by criticality.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    if not request.findings:
        return {
            "metadata": {"total_findings": 0},
            "prioritized_vulnerabilities": [],
        }

    # Convert Pydantic models to dicts for the prioritizer
    findings = []
    for f in request.findings:
        entry = f.model_dump(exclude_none=True)
        entry["_hash"] = f"{f.scanner}:{f.title}"[:12]
        findings.append(entry)

    result = prioritize_with_openai(
        findings, model=request.model, api_key=OPENAI_API_KEY
    )
    return result


@app.post("/api/v1/scan-results")
async def ingest_scan_results(request: ScanResultsRequest):
    """
    Accept raw scanner output, parse it, and prioritize.

    Supported scanners: fickling, semgrep, modelscan, picklescan, osv-scanner
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    scanner = request.scanner.lower().replace("-", "").replace("_", "")
    findings = []

    # Write raw results to temp file for parsers that expect files
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        if isinstance(request.results, str):
            tmp.write(request.results)
        else:
            json.dump(request.results, tmp)
        tmp_path = tmp.name

    try:
        if scanner in ("fickling", "safetyresults"):
            findings = parse_fickling_safety_results(tmp_path)
        elif scanner == "semgrep":
            findings = parse_semgrep_json(tmp_path)
        elif scanner == "modelscan":
            findings = parse_modelscan_json(tmp_path)
        elif scanner in ("picklescan",):
            findings = parse_picklescan_txt(tmp_path)
        elif scanner in ("osvscanner", "osv"):
            findings = parse_osv_scanner_json(tmp_path)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown scanner: {request.scanner}. Supported: fickling, semgrep, modelscan, picklescan, osv-scanner",
            )
    finally:
        os.unlink(tmp_path)

    if not findings:
        return {
            "metadata": {"total_findings": 0, "scanner": request.scanner},
            "prioritized_vulnerabilities": [],
        }

    result = prioritize_with_openai(
        findings, model=request.model, api_key=OPENAI_API_KEY
    )
    return result


@app.post("/api/v1/upload-and-scan")
async def upload_and_scan(
    file: UploadFile = File(..., description="Scanner output file (JSON or text)"),
    scanner: str = "auto",
    model: str = "gpt-4o",
):
    """
    Upload a scanner results file, auto-detect format, parse, and prioritize.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    content = await file.read()
    filename = file.filename or "upload.json"

    # Write to temp
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=os.path.splitext(filename)[1]
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        findings = []

        # Auto-detect scanner from filename or content
        if scanner == "auto":
            fname_lower = filename.lower()
            if "safety_results" in fname_lower or "fickling" in fname_lower:
                scanner = "fickling"
            elif "semgrep" in fname_lower:
                scanner = "semgrep"
            elif "modelscan" in fname_lower:
                scanner = "modelscan"
            elif "picklescan" in fname_lower:
                scanner = "picklescan"
            elif "osv" in fname_lower:
                scanner = "osv-scanner"
            else:
                # Try all parsers
                findings.extend(parse_fickling_safety_results(tmp_path))
                findings.extend(parse_semgrep_json(tmp_path))
                findings.extend(parse_modelscan_json(tmp_path))
                findings.extend(parse_osv_scanner_json(tmp_path))
                scanner = "auto-detected"

        if not findings:
            s = scanner.lower().replace("-", "").replace("_", "")
            if s in ("fickling", "safetyresults"):
                findings = parse_fickling_safety_results(tmp_path)
            elif s == "semgrep":
                findings = parse_semgrep_json(tmp_path)
            elif s == "modelscan":
                findings = parse_modelscan_json(tmp_path)
            elif s == "picklescan":
                findings = parse_picklescan_txt(tmp_path)
            elif s in ("osvscanner", "osv"):
                findings = parse_osv_scanner_json(tmp_path)

    finally:
        os.unlink(tmp_path)

    if not findings:
        return {
            "metadata": {
                "total_findings": 0,
                "scanner": scanner,
                "filename": filename,
            },
            "prioritized_vulnerabilities": [],
        }

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        h = f.get("_hash", "")
        if h not in seen:
            seen.add(h)
            unique.append(f)

    result = prioritize_with_openai(unique, model=model, api_key=OPENAI_API_KEY)
    result["metadata"]["filename"] = filename
    result["metadata"]["scanner"] = scanner
    return result


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

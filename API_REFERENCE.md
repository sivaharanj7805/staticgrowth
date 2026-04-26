# AI Sentinel — API Reference

Base URL: `http://localhost:8000`

All endpoints are **POST**. The other repo sends a request with a JSON body, and this repo responds with the data.

Interactive docs available at `/docs` (Swagger UI) and `/redoc` (ReDoc).

---

## Scan Lifecycle Endpoints

These endpoints allow you to start a scan, track its progress, and retrieve results. All accept `scan_id` in the request body.

---

### POST `/api/v1/scan`

Start a new background security scan across all 14 scanners.

**Request Body (JSON):**

| Field        | Type    | Default | Description                              |
|--------------|---------|---------|------------------------------------------|
| `target_dir` | string  | `"."`   | Directory to scan                        |
| `config_dir` | string  | `null`  | Optional configs directory               |
| `prioritize` | boolean | `false` | Run AI prioritization after scan         |
| `model`      | string  | `"gpt-4o"` | OpenAI model for prioritization      |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target_dir": "./sentinel-test-goat", "prioritize": true}'
```

**Response (200):**

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "queued",
  "message": "Scan started"
}
```

---

### POST `/api/v1/scan/progress`

Get the current progress of a scan as a percentage from 0 to 100.

**Request Body (JSON):**

| Field     | Type   | Required | Description         |
|-----------|--------|----------|---------------------|
| `scan_id` | string | yes      | The scan identifier |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/scan/progress \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (200) — Scan in progress:**

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "running",
  "progress_percent": 57,
  "scanners_completed": 8,
  "total_scanners": 14,
  "current_scanner": "ModelAudit"
}
```

**Response (200) — Scan completed:**

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "completed",
  "progress_percent": 100,
  "scanners_completed": 14,
  "total_scanners": 14,
  "current_scanner": null
}
```

**Response (404):**

```json
{
  "detail": "Scan not found"
}
```

---

### POST `/api/v1/scan/summary`

Get the total number of vulnerabilities categorized by severity: **Critical**, **High**, **Medium**, and **Low**.

**Request Body (JSON):**

| Field     | Type   | Required | Description         |
|-----------|--------|----------|---------------------|
| `scan_id` | string | yes      | The scan identifier |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/scan/summary \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (200) — Scan completed:**

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "completed",
  "total_vulnerabilities": 5,
  "severity_counts": {
    "Critical": 2,
    "High": 1,
    "Medium": 2,
    "Low": 0
  }
}
```

**Response (200) — Scan still running:**

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "running",
  "message": "Scan has not completed yet. Poll /scan/progress to check status.",
  "severity_counts": null,
  "total_vulnerabilities": null
}
```

---

### POST `/api/v1/scan/findings`

Get all individual findings from a completed scan. Each finding includes:

- **Metadata** — title, description, scanner name, and AI enrichment (if prioritization was enabled)
- **Category** — one of the five canonical categories:
  - `Secrets Exposure`
  - `Artifact Integrity Risk`
  - `Dependency Risk`
  - `Provenance Issues`
  - `Configuration Risk`
- **Artifact** — the specific file path where the vulnerability was found

**Request Body (JSON):**

| Field     | Type   | Required | Description         |
|-----------|--------|----------|---------------------|
| `scan_id` | string | yes      | The scan identifier |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/scan/findings \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

**Response (200):**

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "completed",
  "total_findings": 5,
  "findings": [
    {
      "id": "dbd28a45b5a4",
      "severity": "Critical",
      "category": "Artifact Integrity Risk",
      "title": "Use of unsafe operator 'system' from module 'nt'",
      "description": "Use of unsafe operator 'system' from module 'nt'",
      "artifact": "sentinel-test-goat/models/malicious_model.pkl",
      "scanner": "ModelScan",
      "line": null,
      "indicators": {},
      "priority_rank": 1,
      "cvss_estimate": 9.8,
      "exploit_likelihood": "HIGH",
      "blast_radius": "FULL_SYSTEM",
      "attack_vector": "Deserialization of a malicious pickle file that executes 'system' command.",
      "remediation": "Remove or replace the use of 'system' calls in the model file.",
      "justification": "Arbitrary code execution via pickle deserialization is critical."
    },
    {
      "id": "41d949db7c4f",
      "severity": "Medium",
      "category": "Artifact Integrity Risk",
      "title": "ModelAudit finding in undocumented_model.h5",
      "description": "File type validation failed: extension indicates hdf5 but magic bytes indicate unknown.",
      "artifact": "sentinel-test-goat/models/undocumented_model.h5",
      "scanner": "ModelAudit",
      "line": null,
      "indicators": {}
    }
  ]
}
```

**Finding fields (always present):**

| Field         | Type        | Description                                              |
|---------------|-------------|----------------------------------------------------------|
| `id`          | string      | Unique hash identifier for the finding                   |
| `severity`    | string      | One of: `Critical`, `High`, `Medium`, `Low`              |
| `category`    | string      | One of the 5 canonical categories (see above)            |
| `title`       | string      | Short title describing the vulnerability                 |
| `description` | string      | Detailed explanation of the finding                      |
| `artifact`    | string/null | File path where the vulnerability was found              |
| `scanner`     | string      | Name of the scanner that detected this finding           |
| `line`        | int/null    | Line number in the file (if applicable)                  |
| `indicators`  | object      | Additional scanner-specific metadata                     |

**Finding fields (present when AI prioritization is enabled):**

| Field                | Type        | Description                                           |
|----------------------|-------------|-------------------------------------------------------|
| `priority_rank`      | int         | Priority ranking (1 = most critical)                  |
| `cvss_estimate`      | float       | Estimated CVSS score (0.0-10.0)                       |
| `exploit_likelihood` | string      | `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, or `THEORETICAL`|
| `blast_radius`       | string      | `FULL_SYSTEM`, `SERVICE`, `COMPONENT`, or `MINIMAL`   |
| `attack_vector`      | string      | Description of how the vulnerability could be exploited|
| `remediation`        | string      | Specific actionable fix                               |
| `justification`      | string      | Explanation of the priority ranking                   |

---

### POST `/api/v1/scans`

List all scans with their current status and progress. No request body required (send `{}`).

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response (200):**

```json
{
  "scans": [
    {
      "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "status": "completed",
      "progress_percent": 100,
      "target_dir": "./sentinel-test-goat",
      "started_at": "2026-04-25T12:00:00+00:00",
      "completed_at": "2026-04-25T12:05:28+00:00"
    }
  ]
}
```

---

## Utility Endpoints

These existing endpoints provide direct access to parsing and prioritization without running the full scanner suite.

---

### GET `/api/v1/health`

Health check endpoint. This is the only GET endpoint.

**Example Request:**

```bash
curl http://localhost:8000/api/v1/health
```

**Response (200):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-04-25T12:00:00+00:00",
  "openai_configured": true
}
```

---

### POST `/api/v1/prioritize`

Send pre-parsed findings directly for AI prioritization. Does not run scanners.

**Request Body (JSON):**

| Field      | Type   | Default    | Description                             |
|------------|--------|------------|-----------------------------------------|
| `findings` | array  | (required) | Array of finding objects                |
| `model`    | string | `"gpt-4o"` | OpenAI model to use                    |

Each finding object:

| Field              | Type        | Description                      |
|--------------------|-------------|----------------------------------|
| `scanner`          | string      | Scanner name                     |
| `scanner_severity` | string      | Raw severity from scanner        |
| `title`            | string      | Finding title                    |
| `description`      | string      | Finding description              |
| `category`         | string      | Finding category                 |
| `file`             | string/null | File path                        |
| `line`             | int/null    | Line number                      |
| `indicators`       | object      | Additional metadata              |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/prioritize \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [
      {
        "scanner": "ModelScan",
        "scanner_severity": "CRITICAL",
        "title": "Use of unsafe operator system from module nt",
        "description": "Pickle deserialization vulnerability",
        "category": "Model Artifact",
        "file": "models/malicious_model.pkl"
      }
    ],
    "model": "gpt-4o"
  }'
```

**Response (200):**

```json
{
  "metadata": {
    "generated_at": "2026-04-25T12:00:00+00:00",
    "model_used": "gpt-4o",
    "total_findings": 1,
    "severity_summary": {"CRITICAL": 1},
    "scanners_represented": ["ModelScan"]
  },
  "prioritized_vulnerabilities": [...]
}
```

---

### POST `/api/v1/scan-results`

Send raw scanner output for parsing and AI prioritization.

**Request Body (JSON):**

| Field     | Type          | Default    | Description                                                        |
|-----------|---------------|------------|--------------------------------------------------------------------|
| `scanner` | string        | (required) | Scanner name: `fickling`, `semgrep`, `modelscan`, `picklescan`, `osv-scanner` |
| `results` | object/string | (required) | Raw scanner output (JSON object/array or text)                     |
| `model`   | string        | `"gpt-4o"` | OpenAI model to use                                               |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/scan-results \
  -H "Content-Type: application/json" \
  -d '{
    "scanner": "semgrep",
    "results": {"results": [], "errors": []},
    "model": "gpt-4o"
  }'
```

---

### POST `/api/v1/upload-and-scan`

Upload a scanner results file. The API auto-detects the scanner format, parses findings, and returns AI-prioritized results.

**Request (multipart/form-data):**

| Field     | Type   | Default  | Description                               |
|-----------|--------|----------|-------------------------------------------|
| `file`    | file   | (required) | Scanner output file (JSON or text)       |
| `scanner` | string | `"auto"` | Scanner name or `auto` for auto-detection |
| `model`   | string | `"gpt-4o"` | OpenAI model to use                    |

**Example Request:**

```bash
curl -X POST http://localhost:8000/api/v1/upload-and-scan \
  -F "file=@semgrep-results.json" \
  -F "scanner=semgrep"
```

---

## Category Mapping

Scanner findings are mapped to five canonical categories:

| Canonical Category        | Source Scanner Categories                                       |
|---------------------------|-----------------------------------------------------------------|
| **Secrets Exposure**      | Code SAST (Semgrep, CodeQL)                                    |
| **Artifact Integrity Risk** | Model Artifact, Pickle Deserialization, Supply Chain          |
| **Dependency Risk**       | Dependency CVE, Binary CVE, Dependency Policy                   |
| **Provenance Issues**     | SBOM, Agent Architecture                                        |
| **Configuration Risk**    | Prompt Regression, Pipeline Errors, Broken Scanners             |

## Severity Normalization

Scanner severities are normalized to four levels:

| Normalized | Raw Values                      |
|------------|---------------------------------|
| **Critical** | `CRITICAL`                    |
| **High**     | `HIGH`                        |
| **Medium**   | `MEDIUM`, `WARNING`           |
| **Low**      | `LOW`, `INFO`, `INFORMATIONAL`|

## Typical Workflow

1. **Start a scan:** `POST /api/v1/scan` with the target directory — returns `scan_id`
2. **Poll progress:** `POST /api/v1/scan/progress` with `scan_id` until `progress_percent` is `100`
3. **Get severity summary:** `POST /api/v1/scan/summary` with `scan_id` for counts by severity
4. **Get all findings:** `POST /api/v1/scan/findings` with `scan_id` for full details
5. **Display in dashboard:** Use the JSON responses to populate your other repo's UI

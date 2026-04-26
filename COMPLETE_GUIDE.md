# AI Sentinel -- Complete Repository Guide

Everything you need to know about this repository: every file, every script, every config, how to run it, deploy it, test it, tweak it, and extend it.

---

## Table of Contents

1. [What This Project Is](#1-what-this-project-is)
2. [Repository File Map](#2-repository-file-map)
3. [Core Architecture](#3-core-architecture)
4. [The 6-Layer Security Model](#4-the-6-layer-security-model)
5. [The 16+ Security Tools](#5-the-16-security-tools)
6. [File-by-File Breakdown](#6-file-by-file-breakdown)
   - [Root Files](#61-root-files)
   - [scripts/ Directory](#62-scripts-directory)
   - [api/ Directory](#63-api-directory)
   - [configs/ Directory](#64-configs-directory)
   - [tests/ Directory](#65-tests-directory)
   - [docs/ Directory](#66-docs-directory)
   - [.github/workflows/ Directory](#67-githubworkflows-directory)
   - [infra/ Directory (Container Apps)](#68-infra-directory-container-apps)
   - [terraform/ Directory (VM-based)](#69-terraform-directory-vm-based)
   - [sentinel-test-goat/ Directory](#610-sentinel-test-goat-directory)
   - [Model Fixture Files (Root)](#611-model-fixture-files-root)
   - [sentinel-results/ Directory](#612-sentinel-results-directory)
7. [How to Install](#7-how-to-install)
8. [How to Run Scans](#8-how-to-run-scans)
9. [How to Use the API](#9-how-to-use-the-api)
10. [How to Use Azure AI Foundry Integration](#10-how-to-use-azure-ai-foundry-integration)
11. [How to Configure AI Prioritization (OpenAI)](#11-how-to-configure-ai-prioritization-openai)
12. [How to Generate the PDF Report](#12-how-to-generate-the-pdf-report)
13. [How to Run Tests](#13-how-to-run-tests)
14. [How to Change/Add Test Fixtures](#14-how-to-changeadd-test-fixtures)
15. [How to Deploy with Terraform (VM-Based)](#15-how-to-deploy-with-terraform-vm-based)
16. [How to Deploy with Terraform (Container Apps)](#16-how-to-deploy-with-terraform-container-apps)
17. [How to Tweak Terraform Scripts](#17-how-to-tweak-terraform-scripts)
18. [How to Deploy with Docker (Local)](#18-how-to-deploy-with-docker-local)
19. [How to Configure Each Scanner](#19-how-to-configure-each-scanner)
20. [How to Add a New Scanner Tool](#20-how-to-add-a-new-scanner-tool)
21. [How CI/CD Works](#21-how-cicd-works)
22. [How to Use the Test Goat Project](#22-how-to-use-the-test-goat-project)
23. [Environment Variables Reference](#23-environment-variables-reference)
24. [Makefile Targets Reference](#24-makefile-targets-reference)
25. [API Endpoints Reference](#25-api-endpoints-reference)
26. [Troubleshooting](#26-troubleshooting)

---

## 1. What This Project Is

AI Sentinel is an orchestration layer for AI/ML security scanning. It chains 16+ open-source security tools into a unified pipeline that covers:

- Static code analysis (SAST)
- AI agent architecture auditing
- ML model artifact scanning (pickle exploits, trojaned models, backdoors)
- LLM prompt regression testing
- Dependency vulnerability scanning (CVEs, malware, typosquatting)
- Software Bill of Materials (SBOM) generation and governance

It does not replace any tool. It makes them work together with one command (`make scan`), one configuration surface (`configs/`), and one unified report.

The project provides three interfaces:
1. **CLI/Makefile** -- run scans from the command line
2. **Python API** -- `main.py` end-to-end pipeline or `scripts/sentinel-scan.py` programmatic engine
3. **REST API** -- FastAPI server (`api/app.py`) for remote scanning and vulnerability prioritization

---

## 2. Repository File Map

```
ai-sentinel/
|
|-- main.py                         # End-to-end pipeline entrypoint
|-- Makefile                        # All scan targets (make help)
|-- Dockerfile                      # Container with all 16+ tools
|-- pyproject.toml                  # Python project metadata & deps
|-- .gitignore                      # Git exclusions
|-- .dockerignore                   # Docker build exclusions
|-- README.md                       # Project overview
|-- API_REFERENCE.md                # API endpoint docs
|-- generate_all_fixtures.py        # Multi-format fixture generator (root-level)
|-- sentinel-report.pdf             # Generated PDF report (gitignored)
|-- safety_results.json             # Fickling scan output (runtime)
|-- prioritized_vulnerabilities.json# AI prioritization output (runtime)
|
|-- api/
|   |-- app.py                      # FastAPI REST server
|   |-- requirements.txt            # All Python dependencies
|
|-- scripts/
|   |-- sentinel-scan.py            # Core scanning engine (SentinelEngine class)
|   |-- azure_fetch.py              # Azure AI Foundry model discovery & download
|   |-- prioritize_vulnerabilities.py # OpenAI-powered vulnerability prioritizer
|   |-- generate-pdf-report.py      # Full 6-layer PDF report generator
|   |-- generate_test_goat.py       # Goat project generator (vulnerable test app)
|   |-- install.sh                  # Tool installer (minimal/full)
|   |-- scan-code.sh                # Layer 1: Semgrep + CodeQL
|   |-- scan-agents.sh              # Layer 1b: Agentic Radar + MCP-Scan
|   |-- scan-models.sh              # Layer 2: ModelScan + Picklescan + etc.
|   |-- scan-prompts.sh             # Layer 3: Promptfoo
|   |-- scan-deps.sh                # Layer 4: OSV-Scanner + vet + CVE-Bin-Tool
|   |-- scan-sbom.sh                # Layer 5: AIsbom + Syft + CycloneDX merge
|   |-- report.sh                   # Unified markdown report generator
|   |-- validate-scanners.sh        # Pickle-Fuzzer scanner validation
|   |-- test_openai.py              # OpenAI connectivity test
|   |-- test_prioritize.py          # Prioritizer unit test
|
|-- configs/
|   |-- semgrep.yml                 # Custom AI/ML Semgrep rules
|   |-- promptfoo.yml               # OWASP LLM Top 10 prompt tests
|   |-- veritensor.yml              # License firewall + pickle allowlists
|   |-- vet-policy.yml              # SafeDep vet CEL policies
|   |-- dependency-track.env.example# Dependency-Track connection template
|
|-- tests/
|   |-- test-scanners.sh            # Ground truth scanner validation
|   |-- fixtures/
|       |-- generate-fixtures.py    # Fixture generator (pickle-focused)
|       |-- manifest.json           # Ground truth metadata for all fixtures
|       |-- malicious-*.pkl         # Malicious pickle test files
|       |-- safe-*.pkl/pt/onnx/etc  # Clean baseline test files
|
|-- docs/
|   |-- ARCHITECTURE.md             # 6-layer model, data flow, threat model
|   |-- TOOL-EVALUATION.md          # Tool strengths/limitations
|   |-- ADDING-TOOLS.md             # How to add a new scanner
|
|-- .github/workflows/
|   |-- pr-scan.yml                 # Fast PR gate (~2 min)
|   |-- full-scan.yml               # Full 6-layer scan on push to main
|   |-- nightly-deep.yml            # CodeQL + BAIT + Pickle-Fuzzer (2 AM cron)
|
|-- infra/                          # Terraform: Azure Container Apps deployment
|   |-- main.tf                     # ACR, Container App, Key Vault, Storage
|   |-- variables.tf                # Configurable variables
|   |-- outputs.tf                  # API URL, ACR server, etc.
|   |-- terraform.tfvars.example    # Example variable values
|   |-- deploy.ps1                  # One-command PowerShell deploy script
|
|-- terraform/                      # Terraform: Azure VM deployment (alternative)
|   |-- main.tf                     # VNet, NSG, VM with cloud-init Docker
|   |-- variables.tf                # VM size, IP restrictions, etc.
|   |-- outputs.tf                  # VM IP, API URL
|   |-- terraform.tfvars.example    # Example variable values
|
|-- sentinel-test-goat/             # Vulnerable test project for validation
|   |-- src/vulnerable_app.py       # Code with hardcoded secrets, injections
|   |-- models/                     # Malicious pkl, safe safetensors, dummy h5
|   |-- prompts/                    # Promptfoo config + system prompt
|   |-- config/                     # Insecure MCP server config
|   |-- requirements.txt            # Dependencies with known CVEs
|
|-- sentinel-results/               # Timestamped scan outputs (gitignored)
|   |-- <timestamp>/
|       |-- code/                   # Semgrep JSON/SARIF, CodeQL SARIF
|       |-- agents/                 # Agentic Radar, MCP-Scan text output
|       |-- models/                 # ModelScan, Picklescan, Fickling results
|       |-- prompts/                # Promptfoo JSON results
|       |-- deps/                   # OSV-Scanner, vet, CVE-Bin-Tool results
|       |-- sbom/                   # AIsbom, Syft, merged SBOM
|       |-- REPORT.md               # Unified markdown report
|       |-- all-findings.json       # Combined findings JSON
|
|-- malicious-*.pkl/pt/h5/onnx/etc # Root-level test fixtures (all formats)
|-- safe-*.pkl/pt/safetensors/etc   # Root-level safe baseline fixtures
```

---

## 3. Core Architecture

### Pipeline Flow

```
[Azure AI Foundry] --(optional fetch)--> [Local Model Files]
                                              |
                                              v
                                   [SentinelEngine.run_all()]
                                              |
              +-------------------------------+-------------------------------+
              |               |               |               |               |
         Layer 1          Layer 1b        Layer 2         Layer 3         Layer 4/5
        Code SAST      Agent Arch     Model Artifacts   Prompt Test    Deps + SBOM
              |               |               |               |               |
              +-------------------------------+-------------------------------+
                                              |
                                              v
                                   [Deduplication by content hash]
                                              |
                                              v
                              [OpenAI Prioritization (optional)]
                                              |
                                              v
                              [JSON output + Markdown/PDF report]
```

### Two Execution Modes

1. **Shell-script mode** (`make scan`): Each layer has its own bash script that invokes CLI tools directly. Results go to `sentinel-results/<timestamp>/`. The `report.sh` script aggregates everything into `REPORT.md`.

2. **Python engine mode** (`python main.py` or the API): The `SentinelEngine` class in `scripts/sentinel-scan.py` contains Python-native scanner classes and CLI adapter classes. All findings are unified into `Finding` objects, deduplicated by content hash, and returned as a single JSON structure.

### Key Classes (sentinel-scan.py)

- **`Finding`** -- Unified representation of a vulnerability. Fields: `scanner`, `category`, `severity`, `title`, `description`, `file`, `line`, `indicators`, `_hash`.
- **`BaseScanner`** -- Abstract base class. Subclasses implement `scan(target_dir, config_dir) -> list[Finding]`.
- **`ModelScanNative`**, **`PicklescanNative`**, **`FicklingNative`** -- Python-native scanners that `import` the library directly.
- **`CLIAdapter`** -- Base class for tools that can only be invoked via CLI. Provides `run_cmd(cmd, args, timeout)`.
- **`SemgrepAdapter`**, **`CodeQLAdapter`**, **`OSVScannerAdapter`**, etc. -- CLI wrappers.
- **`SentinelEngine`** -- Orchestrator. Loads all scanners, runs them sequentially, deduplicates findings, returns unified JSON.

---

## 4. The 6-Layer Security Model

| Layer | What It Scans | Tools | Script |
|-------|---------------|-------|--------|
| **1. Code SAST** | Source code for vulnerabilities (injections, hardcoded keys, unsafe deserialization) | Semgrep, CodeQL | `scan-code.sh` |
| **1b. Agent Architecture** | AI agent workflows, MCP configs, tool permissions | Agentic Radar, Snyk Agent Scan (MCP-Scan) | `scan-agents.sh` |
| **2. Model Artifacts** | ML model files for embedded exploits, trojans, backdoors | ModelScan, Picklescan, Fickling, ModelAudit, Veritensor, BAIT | `scan-models.sh` |
| **3. Prompt Testing** | LLM prompt behavior for jailbreaks, PII leakage, regressions | Promptfoo | `scan-prompts.sh` |
| **4. Dependencies** | Project dependencies for known CVEs, malware, typosquatting | OSV-Scanner, SafeDep vet, CVE Binary Tool | `scan-deps.sh` |
| **5. SBOM & Governance** | Software inventory for compliance, audit, and monitoring | AIsbom, Syft, CycloneDX CLI, Dependency-Track | `scan-sbom.sh` |

### Three Scan Tiers

| Tier | When | Time | Tools |
|------|------|------|-------|
| **PR Scan** | Every pull request | ~2 min | Semgrep + ModelScan + Picklescan + OSV-Scanner |
| **Full Scan** | Push to main | ~10 min | All 6 layers |
| **Nightly Deep** | Cron (2 AM UTC) | ~30-60 min | CodeQL + BAIT + Pickle-Fuzzer validation |

---

## 5. The 16+ Security Tools

| # | Tool | Language | Install Method | What It Does |
|---|------|----------|---------------|-------------|
| 1 | Semgrep | Python (OCaml core) | `pip install semgrep` | Static analysis with custom AI/ML rules |
| 2 | CodeQL | C++ binary | Download tarball | Deep semantic code analysis |
| 3 | Agentic Radar | Python | `pip install agentic-radar` | Agent framework security analysis |
| 4 | Snyk Agent Scan | Python | `pip install snyk-agent-scan` | MCP server configuration scanning |
| 5 | ModelScan | Python | `pip install modelscan` | ML model artifact vulnerability scanning |
| 6 | Picklescan | Python | `pip install picklescan` | Pickle-specific dangerous import detection |
| 7 | Fickling | Python | `pip install fickling[torch]` | Deep pickle forensic analysis |
| 8 | ModelAudit | Python | `pip install modelaudit[all]` | Multi-format model auditing |
| 9 | Veritensor | Python | `pip install veritensor[all]` | Supply chain + dataset verification |
| 10 | BAIT | Python | Source install | Behavioral backdoor detection |
| 11 | Promptfoo | Node.js | `npm install -g promptfoo` | LLM prompt regression testing |
| 12 | OSV-Scanner | Go | `go install` | Broadest CVE advisory database |
| 13 | SafeDep vet | Go | Download binary | Malware detection + reachability analysis |
| 14 | CVE Binary Tool | Python | `pip install cve-bin-tool` | Binary-level CVE scanning |
| 15 | AIsbom | Python | `pip install aisbom-cli` | AI model SBOM generation |
| 16 | Syft | Go | Anchore install script | Infrastructure SBOM generation |
| 17 | CycloneDX CLI | .NET | Download binary | SBOM merge/convert/diff |
| 18 | Pickle-Fuzzer | Rust | `cargo install pickle-fuzzer` | Adversarial pickle generation for scanner validation |

---

## 6. File-by-File Breakdown

### 6.1 Root Files

#### `main.py` -- End-to-End Pipeline

The primary entrypoint. Runs the complete 4-phase pipeline:

1. **Phase 1: Azure Fetch** -- Optionally connects to Azure AI Foundry to discover and download registered models.
2. **Phase 2: Scanning** -- Creates a `SentinelEngine` instance and runs all 16+ scanners.
3. **Phase 3: AI Prioritization** -- Optionally sends findings to OpenAI GPT for intelligent prioritization (CVSS scoring, exploit likelihood, remediation advice).
4. **Phase 4: Reporting** -- Writes `all-findings.json` and generates `REPORT.md`.

**Key CLI arguments:**
```bash
python main.py --target ./your-project        # Directory to scan
python main.py --prioritize --model gpt-4o    # Enable AI prioritization
python main.py --azure-subscription-id X \
               --azure-resource-group Y \
               --azure-workspace-name Z \
               --azure-scan-all               # Fetch all Azure models first
```

#### `Makefile` -- Single Entry Point

Every operation you can perform is a `make` target. Run `make help` to see all of them.

Key targets:
- `make install` / `make install-minimal` -- Install tools
- `make scan TARGET=./project` -- Full 6-layer scan
- `make scan-fast TARGET=./project` -- Fast PR-level scan
- `make scan-code`, `scan-models`, `scan-deps`, `scan-prompts`, `scan-agents`, `scan-sbom` -- Individual layers
- `make report` -- Generate markdown report
- `make report-pdf` -- Full scan + PDF report
- `make test` -- Validate scanners against ground truth
- `make prioritize` -- AI-prioritize findings with OpenAI
- `make check-tools` -- Show installed/missing tools
- `make clean` -- Delete all scan results

#### `Dockerfile` -- Container Image

Builds a container with **all 16+ tools** pre-installed:
- Base: `python:3.12-slim`
- Installs: Node.js 20 (for Promptfoo), Go 1.22 (for OSV-Scanner), Rust (for Pickle-Fuzzer)
- Installs all Python packages from `api/requirements.txt` plus Semgrep
- Installs non-Python CLIs: Promptfoo, OSV-Scanner, Syft, CodeQL, SafeDep vet, CycloneDX CLI, Pickle-Fuzzer
- Exposes port 8000 and runs the FastAPI server via uvicorn
- Health check hits `/api/v1/health`

#### `pyproject.toml` -- Project Metadata

Defines optional dependency groups:
- `minimal`: modelscan, aisbom-cli
- `scanning`: All Python scanning libraries
- `agents`: agentic-radar, snyk-agent-scan
- `azure`: azure-ai-ml, azure-identity
- `dev`: pytest, ruff

#### `generate_all_fixtures.py` -- Multi-Format Fixture Generator

Generates test fixtures across **12 model file formats**: pickle, PyTorch (.pt/.pth), joblib, numpy (.npy/.npz), Keras/HDF5 (.h5/.hdf5), ONNX, TFLite, Hugging Face .bin, safetensors, GGUF, dill/cloudpickle, and zip/tar.gz archives. Every malicious fixture uses harmless payloads (echo/print) but contains the exact opcode patterns that real attacks use.

Run it:
```bash
python generate_all_fixtures.py                  # default: ./tests/fixtures
python generate_all_fixtures.py -o ./my-fixtures  # custom output dir
```

---

### 6.2 scripts/ Directory

#### `sentinel-scan.py` -- Core Scanning Engine

This is the heart of AI Sentinel. Contains:

- **`SentinelEngine`** class: Instantiated with a target directory. Loads all 13 scanner classes. `run_all()` executes them sequentially, deduplicates findings by SHA-256 content hash, and returns a unified JSON dict.

- **Native Python scanners** (import the library directly):
  - `ModelScanNative` -- Calls `modelscan.modelscan.ModelScan().scan(file)`
  - `PicklescanNative` -- Calls `picklescan.scanner.scan_directory_path(dir)`
  - `FicklingNative` -- Calls `fickling.fickle.Pickled.load(file).analyze()`

- **CLI adapters** (wrap command-line tools):
  - `SemgrepAdapter` -- Runs `semgrep scan --config p/security-audit`
  - `CodeQLAdapter` -- Creates database, runs `python-security-extended.qls`
  - `OSVScannerAdapter` -- Runs `osv-scanner scan --format json`
  - `PromptfooAdapter` -- Runs `promptfoo eval --config <config>`
  - `SyftAdapter` -- Runs `syft scan -o cyclonedx-json`
  - `CVEBinToolAdapter` -- Runs `cve-bin-tool --format json`
  - `AgenticRadarAdapter` -- Runs `agentic-radar scan`
  - `SnykAgentScanAdapter` -- Runs `snyk-agent-scan` or `mcp-scan`
  - `VeritensorAdapter` -- Runs `veritensor scan` per model file
  - `ModelAuditAdapter` -- Runs `modelaudit <file> --format json`

The `find_models()` helper searches the target directory recursively for files matching model extensions: `.pt`, `.pth`, `.pkl`, `.pickle`, `.h5`, `.hdf5`, `.onnx`, `.safetensors`, `.gguf`, `.joblib`, `.npy`, `.bin`, `.tflite`.

#### `azure_fetch.py` -- Azure AI Foundry Integration

Connects to Azure ML Workspaces (AI Foundry) using `DefaultAzureCredential`. Three modes:

1. **Interactive discovery** (`--discover`): Lists all registered models in a formatted table, prompts user to select by index/range.
2. **Headless filtering** (`--scan-all`, `--filter-name "bert*"`, `--filter-tag "env=production"`, `--filter-type "mlflow_model"`): Automatically selects models matching criteria.
3. **Legacy single-model** (`--model-name X --model-version 2`): Downloads one specific model.

Key functions:
- `list_workspace_models()` -- Returns flat list of `{name, version, type, description, tags, stage}` dicts
- `filter_models()` -- Applies glob/tag/type filters
- `prompt_model_selection()` -- Interactive selection (supports `1,3,5` or `1-5` or `all`)
- `fetch_azure_models()` -- Downloads models to local cache via `ml_client.models.download()`
- `discover_and_fetch()` -- Orchestrates discovery + selection + download

#### `prioritize_vulnerabilities.py` -- AI Prioritization

Parses findings from all scanner output formats, deduplicates them, and sends them to OpenAI for intelligent prioritization.

**Parsers included:**
- `parse_fickling_safety_results()` -- Concatenated JSON objects from Fickling
- `parse_semgrep_json()` -- Semgrep JSON output
- `parse_modelscan_json()` -- ModelScan JSON output
- `parse_picklescan_txt()` -- Picklescan text output
- `parse_osv_scanner_json()` -- OSV-Scanner JSON output
- `parse_vet_json()` -- SafeDep vet JSON output
- `parse_cve_bin_tool_json()` -- CVE Binary Tool JSON output
- `parse_scanner_errors()` -- Detects crashed scanners (coverage gaps)

**`prioritize_with_openai(findings, model, api_key)`:**
- Prepares findings (strips internal hashes, adds IDs, truncates descriptions to 500 chars)
- Chunks to max 40 findings per API call (token limits)
- Sends to OpenAI with a detailed system prompt that instructs the model to return: `priority_rank`, `ai_severity`, `cvss_estimate`, `exploit_likelihood`, `blast_radius`, `attack_vector`, `remediation`, `justification`
- Merges AI results back with original findings
- Returns sorted, ranked list

**CLI usage:**
```bash
# From scan results directory
python scripts/prioritize_vulnerabilities.py -r sentinel-results/20260324-180522

# From Fickling safety_results.json
python scripts/prioritize_vulnerabilities.py -s safety_results.json

# From a directory of JSON files
python scripts/prioritize_vulnerabilities.py -d .

# Dry run (parse only, no OpenAI call)
python scripts/prioritize_vulnerabilities.py -s safety_results.json --dry-run

# Custom model
python scripts/prioritize_vulnerabilities.py -s safety_results.json --model gpt-4o
```

#### `generate-pdf-report.py` -- PDF Report Generator

Generates a comprehensive color-coded PDF report covering all 6 layers. Uses `fpdf2`.

**What the PDF includes:**
- Title page with timestamp, target, fixture counts
- Tool inventory (installed vs. missing)
- Executive summary (total findings, scanner accuracy)
- Color-coded legend (PASS/FAIL/SKIP/FN/FP definitions)
- Layer 1: Semgrep findings detail table with severity coloring
- Layer 1b: Agent architecture findings
- Layer 2: Per-scanner accuracy table + per-file detailed results
- Layer 3: Promptfoo test results
- Layer 4: Dependency CVE table
- Layer 5: SBOM component breakdown
- Fixture inventory with malicious/safe classification
- Detailed model scanner findings per file

**Usage:**
```bash
# Full pipeline: scan fixtures + scan project + generate PDF
python scripts/generate-pdf-report.py --scan-fixtures -o sentinel-report.pdf

# From existing results
python scripts/generate-pdf-report.py --results-dir sentinel-results/20260324-180522 -o report.pdf

# Custom target and fixtures
python scripts/generate-pdf-report.py --scan-fixtures --target ./my-project --fixtures-dir ./my-fixtures
```

#### `install.sh` -- Tool Installer

Two modes:
- `bash scripts/install.sh minimal` -- 5 tools: modelscan, aisbom, syft, osv-scanner, Dependency-Track
- `bash scripts/install.sh full` -- All 16+ tools across pip, npm, go, cargo

The script checks if each tool is already installed before attempting install. Uses helper functions: `pip_install`, `go_install`, `npm_install`, `cargo_install`.

#### Shell Scripts (`scan-*.sh`, `report.sh`, `validate-scanners.sh`)

Each scan script:
1. Reads `$TARGET`, `$RESULTS_DIR`, `$CONFIGS_DIR` from environment
2. Checks if the tool is installed (`command -v`)
3. Runs the tool with appropriate flags, outputs to `$RESULTS_DIR/<layer>/`
4. Gracefully skips missing tools with `|| true`

**`scan-code.sh`**: Runs Semgrep (always) and CodeQL (full mode only). Semgrep uses `p/security-audit` + `p/owasp-top-ten` + custom `configs/semgrep.yml`.

**`scan-models.sh`**: Finds all model files by extension. Runs ModelScan and Picklescan (always). In full mode, also runs ModelAudit, Veritensor, BAIT, and Fickling. Fickling only runs on pickle-compatible files (.pkl, .pickle, .pt, .pth, .joblib, .bin).

**`scan-agents.sh`**: Auto-detects agent framework (LangGraph, CrewAI, OpenAI Agents, AutoGen). Runs Agentic Radar. Runs MCP-Scan if MCP config files are found.

**`scan-prompts.sh`**: Looks for `promptfooconfig.yaml` in the target, then falls back to `configs/promptfoo.yml`.

**`scan-deps.sh`**: Runs OSV-Scanner (always). In full mode, also SafeDep vet (with CEL policy if available) and CVE Binary Tool.

**`scan-sbom.sh`**: Runs AIsbom (model SBOM), Syft (infrastructure SBOM), merges with CycloneDX CLI, and optionally uploads to Dependency-Track if `DT_URL`, `DT_API_KEY`, `DT_PROJECT_UUID` are set.

**`report.sh`**: Generates `REPORT.md` by checking which result files exist and counting findings from each JSON file.

**`validate-scanners.sh`**: Two-phase validation: (1) Run `tests/test-scanners.sh` against ground truth fixtures, (2) Generate 50 adversarial pickle files with Pickle-Fuzzer and measure each scanner's detection rate.

#### `generate_test_goat.py` -- Vulnerable Test Project Generator

Generates the `sentinel-test-goat/` directory containing deliberately vulnerable code, malicious models, insecure configurations, and CVE-laden dependencies. Purpose: end-to-end validation that AI Sentinel catches everything.

---

### 6.3 api/ Directory

#### `app.py` -- FastAPI REST Server

The cloud API wraps the scanning engine and prioritizer.

**Core components:**
- **Category mapping**: Maps raw scanner categories to 5 canonical categories: Secrets Exposure, Artifact Integrity Risk, Dependency Risk, Provenance Issues, Configuration Risk.
- **Severity normalization**: Maps all severity strings to Critical/High/Medium/Low.
- **In-memory scan store**: `_scans` dict (thread-safe with `_scans_lock`) tracks background scan progress.

**Endpoints (detailed in section 25):**
- `POST /api/v1/scan` -- Start background scan
- `POST /api/v1/scan/progress` -- Poll scan progress
- `POST /api/v1/scan/summary` -- Get severity counts
- `POST /api/v1/scan/findings` -- Get all findings with AI enrichment
- `POST /api/v1/scans` -- List all scans
- `GET /api/v1/health` -- Health check
- `POST /api/v1/prioritize` -- Prioritize pre-parsed findings
- `POST /api/v1/scan-results` -- Parse raw scanner output and prioritize
- `POST /api/v1/upload-and-scan` -- Upload file, auto-detect format, prioritize

**CORS**: Enabled for all origins (development mode). Restrict in production.

#### `requirements.txt` -- Python Dependencies

All pip-installable packages:
- **Core API**: fastapi, uvicorn, python-multipart, pydantic
- **AI Integration**: openai
- **Azure**: azure-identity, azure-ai-ml
- **PDF**: fpdf2
- **Scanning**: modelscan, picklescan, fickling, modelaudit, veritensor, agentic-radar, snyk-agent-scan, cve-bin-tool, aisbom-cli, cyclonedx-bom
- **ML Frameworks**: torch, numpy, h5py, onnx, safetensors, joblib, dill, cloudpickle
- **Dev**: pytest, ruff

Non-Python tools (CodeQL, OSV-Scanner, Syft, Promptfoo, SafeDep vet, CycloneDX CLI, Pickle-Fuzzer) are installed via Dockerfile or install.sh.

---

### 6.4 configs/ Directory

#### `semgrep.yml` -- Custom AI/ML Semgrep Rules

10 custom rules targeting AI/ML-specific vulnerabilities:

| Rule ID | Severity | What It Catches |
|---------|----------|----------------|
| `unsafe-pickle-load` | ERROR | `pickle.load()` without `weights_only=True` |
| `unsafe-torch-load` | ERROR | `torch.load()` without `weights_only=True` |
| `llm-output-exec` | ERROR | `exec()`/`eval()` on LLM output |
| `llm-output-subprocess` | WARNING | Shell commands with dynamic input |
| `unsanitized-prompt-template` | WARNING | User input in f-strings/format() for prompts |
| `hardcoded-openai-key` | ERROR | `"sk-..."` literal strings |
| `hardcoded-anthropic-key` | ERROR | `"sk-ant-..."` literal strings |
| `model-endpoint-no-auth` | WARNING | Model predict endpoints without auth decorators |
| `model-endpoint-no-rate-limit` | WARNING | Model predict endpoints without rate limiting |

**How to add a rule:** Add a new YAML block under `rules:` with `id`, `patterns`, `message`, `languages`, `severity`, and `metadata` (CWE, OWASP).

#### `promptfoo.yml` -- OWASP LLM Top 10 Test Suite

15 test cases covering all OWASP LLM Top 10 categories:
- LLM01: Prompt Injection (3 tests)
- LLM02: Insecure Output Handling (2 tests)
- LLM03: Training Data Poisoning
- LLM04: Model Denial of Service
- LLM05: Supply Chain Vulnerabilities
- LLM06: Sensitive Information Disclosure (2 tests)
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance
- LLM10: Model Theft
- Functionality regression (2 tests)

**How to customize:**
1. Change the `providers` section from `echo` (placeholder) to your actual LLM:
   ```yaml
   providers:
     - id: openai:gpt-4
     # or
     - id: anthropic:messages:claude-sonnet-4-20250514
   ```
2. Add domain-specific test cases under `tests:`.

#### `veritensor.yml` -- Veritensor Configuration

- **Severity threshold**: CRITICAL (fail the scan on critical findings)
- **License firewall**: Blocks CC-BY-NC, CC-BY-NC-SA, CC-BY-NC-ND, AGPL-3.0, research-only; warns on GPL-2.0/3.0, LGPL-3.0
- **Pickle allowlist**: Allows sklearn, numpy, torch, collections, builtins, copyreg; blocks os, subprocess, sys, shutil, socket, http, requests, urllib, ctypes, importlib, webbrowser
- **Trusted repos**: meta-llama/*, google/*, sentence-transformers/*, microsoft/*, openai/*, stabilityai/*, mistralai/*
- **Output**: SARIF + CycloneDX SBOM

#### `vet-policy.yml` -- SafeDep vet CEL Policies

7 CEL expression policies:
- `block-critical-vulns`: Deny packages with CRITICAL CVEs
- `block-malware`: Deny packages flagged as malware
- `warn-high-vulns`: Warn on HIGH severity CVEs
- `warn-unmaintained`: Warn on OpenSSF Scorecard < 4.0
- `warn-stale`: Warn on packages with no releases in 2+ years
- `warn-copyleft`: Warn on GPL/AGPL licenses
- `block-deprecated`: Deny deprecated packages

#### `dependency-track.env.example`

Template for connecting to a Dependency-Track instance:
```
DT_URL=https://dependency-track.example.com
DT_API_KEY=your-api-key-here
DT_PROJECT_UUID=your-project-uuid-here
```
Copy to `dependency-track.env` and fill in values. This file is gitignored.

---

### 6.5 tests/ Directory

#### `test-scanners.sh` -- Ground Truth Validation

Tests each installed scanner against the fixtures in `tests/fixtures/`. Reads `manifest.json` to know which files are malicious and which are safe. For each file:
- Malicious files MUST be flagged (failure = False Negative)
- Safe files MUST NOT be flagged (failure = False Positive)

Supports `--verbose` flag for per-file details. Exit code 0 = all passed, 1 = failures.

#### `fixtures/generate-fixtures.py` -- Fixture Generator

Generates 15 test fixtures:
- 8 malicious pickles: eval, os.system, subprocess.Popen, socket.socket, exec, nested dict, __import__, webbrowser.open
- 4 safe pickles: PyTorch state dict, sklearn-style, config dict, numpy-style weights
- 3 safe non-pickle: safetensors (header-only), ONNX (minimal protobuf), HDF5 (signature + superblock)

Writes `manifest.json` with metadata for each fixture (file, malicious, category, description, techniques).

---

### 6.6 docs/ Directory

- **`ARCHITECTURE.md`**: 6-layer model diagram, three scan tiers explanation, data flow, output format table, threat model (what it catches, what it doesn't).
- **`TOOL-EVALUATION.md`**: Strengths and limitations of every tool.
- **`ADDING-TOOLS.md`**: Step-by-step guide to add a new scanner: write script, add to install.sh, add to report.sh, update Makefile, wire into CI, add config, test.

---

### 6.7 .github/workflows/ Directory

#### `pr-scan.yml` -- PR Gate (~2 min)

Triggered on: Pull requests to main. Three parallel jobs:
1. **semgrep**: Installs Semgrep, runs with security-audit + owasp-top-ten + custom rules, uploads SARIF to GitHub Security tab.
2. **model-scan**: Checks if model files exist, installs modelscan + picklescan, scans all model files.
3. **osv-scanner**: Uses official `google/osv-scanner-action`, uploads SARIF.

#### `full-scan.yml` -- Full 6-Layer Scan

Triggered on: Push to main, manual dispatch. Six parallel jobs (one per layer) + a report job that runs after all complete:
1. **code-sast**: Semgrep
2. **agent-scan**: Agentic Radar
3. **model-scan**: ModelScan + Picklescan + ModelAudit + Veritensor + Fickling
4. **prompt-test**: Promptfoo (requires `OPENAI_API_KEY` secret)
5. **dep-scan**: OSV-Scanner + CVE Binary Tool
6. **sbom**: AIsbom + Syft (optionally uploads to Dependency-Track via secrets)
7. **report**: Downloads all artifacts, generates `REPORT.md`

#### `nightly-deep.yml` -- Nightly Deep Scan (2 AM UTC)

Triggered on: Cron `0 2 * * *`, manual dispatch. Three jobs:
1. **codeql**: Full CodeQL analysis using `github/codeql-action`
2. **bait**: BAIT behavioral backdoor detection (clones and installs from source)
3. **validate-scanners**: Installs Pickle-Fuzzer (Rust), generates adversarial samples, measures detection rates

---

### 6.8 infra/ Directory (Container Apps)

Azure Container Apps deployment. This is the **production-grade** approach.

#### `main.tf`

Creates:
- **Resource Group**: `rg-aisentinel-prod`
- **Log Analytics Workspace**: For Container Apps monitoring
- **Azure Container Registry (ACR)**: Basic SKU, admin disabled
- **User Assigned Managed Identity**: For ACR pull + Key Vault access
- **Key Vault**: Stores OpenAI API key, access policies for deployer and managed identity
- **Storage Account**: Two blob containers -- `model-uploads` (for model files) and `scan-results` (for scan output)
- **Container App Environment**: Backed by Log Analytics
- **Container App**: Runs `ai-sentinel-api:latest` from ACR, with environment variables for OpenAI key (from secret), storage account, client ID. Has liveness + readiness probes on `/api/v1/health:8000`. Ingress is external on port 8000 with 100% traffic to latest revision.

#### `variables.tf`

| Variable | Default | Description |
|----------|---------|-------------|
| `subscription_id` | (set) | Azure Subscription ID |
| `location` | `eastus2` | Azure region |
| `project_name` | `aisentinel` | Used in resource naming |
| `environment` | `prod` | Deployment environment |
| `openai_api_key` | (sensitive) | OpenAI API key |
| `container_image_tag` | `latest` | Docker image tag |
| `container_cpu` | `1.0` | CPU cores |
| `container_memory` | `2Gi` | Memory |
| `max_replicas` | `3` | Max container replicas |
| `min_replicas` | `0` | Min replicas (scales to 0) |

#### `outputs.tf`

- `api_url` -- Public HTTPS URL of the API
- `acr_login_server` -- ACR login server for docker push
- `resource_group_name`
- `storage_account_name`
- `key_vault_name`
- `swagger_ui_url` -- Swagger UI endpoint

#### `deploy.ps1` -- One-Command Deploy

PowerShell script that automates the full deployment:
1. Validates tools (az, terraform, docker)
2. Checks Azure login
3. `terraform init -upgrade`
4. Creates infrastructure (targeted apply for ACR first)
5. Builds Docker image and pushes to ACR
6. Full `terraform apply` to deploy Container App
7. Prints API URL and Swagger UI URL

Usage:
```powershell
.\infra\deploy.ps1 -OpenAIApiKey "sk-your-key"
.\infra\deploy.ps1 -OpenAIApiKey "sk-your-key" -PlanOnly    # Preview only
.\infra\deploy.ps1 -OpenAIApiKey "sk-your-key" -Destroy      # Tear down
```

---

### 6.9 terraform/ Directory (VM-Based)

Alternative Azure VM deployment. Simpler but less scalable.

#### `main.tf`

Creates:
- **Resource Group**
- **VNet** (10.0.0.0/16) + **Subnet** (10.0.1.0/24)
- **NSG** with strict rules: Allow port 8000 from `allowed_ip` only, Deny SSH (22), Deny RDP (3389), Deny all other inbound
- **Public IP** (Static, Standard SKU)
- **NIC** with the public IP
- **TLS Private Key** (RSA 4096, generated but SSH is blocked by NSG)
- **Linux VM** (Ubuntu 22.04 LTS) with **cloud-init** that:
  1. Installs Docker and git
  2. Clones the repository
  3. Builds the Docker image
  4. Runs the container with `OPENAI_API_KEY` and `OPENAI_MODEL` environment variables, mapping port 8000
  5. Deletes the source code from the VM
  6. Disables SSH entirely

#### `variables.tf`

| Variable | Default | Description |
|----------|---------|-------------|
| `resource_group_name` | `rg-ai-sentinel` | Resource group name |
| `location` | `East US` | Azure region |
| `vm_size` | `Standard_B2s` | VM size (2 vCPU, 4GB RAM) |
| `admin_username` | `azureuser` | VM admin (SSH disabled) |
| `openai_api_key` | (sensitive) | OpenAI API key |
| `openai_model` | `gpt-4o` | OpenAI model for prioritization |
| `allowed_ip` | `*` | CIDR for API access restriction |

#### `outputs.tf`

- `api_url` -- `http://<public_ip>:8000`
- `api_health_check` -- Health endpoint URL
- `api_docs` -- Swagger UI URL
- `vm_public_ip` -- Raw IP address

---

### 6.10 sentinel-test-goat/ Directory

A deliberately vulnerable test project generated by `scripts/generate_test_goat.py`:

- **`src/vulnerable_app.py`**: Hardcoded OpenAI + AWS keys, os.system command injection, path traversal, unsafe yaml.load
- **`models/malicious_model.pkl`**: Pickle with os.system RCE payload
- **`models/safe_weights.safetensors`**: Dummy safe file
- **`models/undocumented_model.h5`**: Model missing metadata (tests SBOM tools)
- **`prompts/promptfooconfig.yaml`**: Jailbreak + PII leakage tests
- **`prompts/system_prompt.txt`**: System prompt for testing
- **`config/mcp_server_config.json`**: MCP config with missing HITL, missing sandboxing, missing loop limits
- **`requirements.txt`**: Known CVEs (requests 2.19.0, urllib3 1.24) + typosquats (requestts, colorama-python)

---

### 6.11 Model Fixture Files (Root)

The root directory contains multi-format test fixtures generated by `generate_all_fixtures.py`. These include malicious and safe variants of: `.pkl`, `.pt`, `.pth`, `.h5`, `.hdf5`, `.onnx`, `.tflite`, `.bin`, `.safetensors`, `.gguf`, `.joblib`, `.npy`, `.npz`, `.dill`, `.cloudpickle`, `.zip`, `.tar.gz`.

---

### 6.12 sentinel-results/ Directory

All scan outputs are stored in timestamped subdirectories:
```
sentinel-results/
  20260324-180522/
    code/semgrep.json, codeql.sarif, codeql-db/
    agents/agentic-radar.txt, mcp-scan.txt
    models/modelscan.json, picklescan.txt, fickling/
    prompts/promptfoo-results.json
    deps/osv-scanner.json, vet.json, cve-bin-tool.json
    sbom/aisbom-models.json, syft-env.json, merged-sbom.json
    REPORT.md
  20260422-191201/
    all-findings.json
    REPORT.md
```

This directory is gitignored.

---

## 7. How to Install

### Minimal Stack (5 tools, ~5 minutes)

```bash
make install-minimal
# or directly:
bash scripts/install.sh minimal
```

Installs: modelscan, aisbom, syft, osv-scanner, and prints Dependency-Track setup instructions.

### Full Stack (16+ tools, ~15 minutes)

```bash
make install
# or directly:
bash scripts/install.sh full
```

Requires: Python 3.10+, pip, npm (for Promptfoo), Go (for OSV-Scanner), optionally Rust (for Pickle-Fuzzer).

### Manual Prerequisites

Some tools require manual installation:
- **CodeQL**: Download from GitHub: `https://github.com/github/codeql-action/releases`
- **SafeDep vet**: Download binary from `https://github.com/safedep/vet/releases`
- **CycloneDX CLI**: Requires .NET 8 SDK or download binary
- **BAIT**: Clone and install from source: `git clone https://github.com/SolidShen/BAIT && pip install -e .`
- **Dependency-Track**: Deploy via Docker

### Azure Integration

```bash
pip install azure-ai-ml azure-identity
# or
pip install ".[azure]"
```

### Verify Installation

```bash
make check-tools
```

---

## 8. How to Run Scans

### Full Scan (All 6 Layers)

```bash
make scan TARGET=./your-ai-project
```

### Fast PR-Level Scan (~2 minutes)

```bash
make scan-fast TARGET=./your-ai-project
```

Runs: Semgrep + ModelScan + Picklescan + OSV-Scanner.

### Individual Layers

```bash
make scan-code    TARGET=./your-project   # Layer 1: Semgrep + CodeQL
make scan-agents  TARGET=./your-project   # Layer 1b: Agentic Radar + MCP-Scan
make scan-models  TARGET=./your-project   # Layer 2: All model scanners
make scan-prompts TARGET=./your-project   # Layer 3: Promptfoo
make scan-deps    TARGET=./your-project   # Layer 4: OSV-Scanner + vet + CVE-Bin-Tool
make scan-sbom    TARGET=./your-project   # Layer 5: AIsbom + Syft + CycloneDX merge
```

### Using Python Directly

```bash
# End-to-end pipeline
python main.py --target ./your-project

# With AI prioritization
python main.py --target ./your-project --prioritize --model gpt-4o

# Just the scanning engine
python scripts/sentinel-scan.py --target ./your-project

# Scan + Azure model fetch + prioritize
python main.py --target ./your-project \
    --azure-subscription-id YOUR_SUB_ID \
    --azure-resource-group YOUR_RG \
    --azure-workspace-name YOUR_WORKSPACE \
    --azure-scan-all \
    --prioritize
```

### Scan the Test Goat

```bash
# Generate the vulnerable test project
python scripts/generate_test_goat.py

# Scan it
python main.py --target ./sentinel-test-goat --prioritize
```

---

## 9. How to Use the API

### Start the Server

```bash
# Direct
uvicorn api.app:app --host 0.0.0.0 --port 8000

# Or via Python
python api/app.py

# Or via Docker
docker build -t ai-sentinel .
docker run -p 8000:8000 -e OPENAI_API_KEY=sk-your-key ai-sentinel
```

### Swagger UI

Open `http://localhost:8000/docs` for interactive API documentation.

### Example: Start a Scan

```bash
# Start scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target_dir": ".", "prioritize": true}'
# Returns: {"scan_id": "abc-123", "status": "queued"}

# Poll progress
curl -X POST http://localhost:8000/api/v1/scan/progress \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123"}'

# Get summary
curl -X POST http://localhost:8000/api/v1/scan/summary \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123"}'

# Get all findings
curl -X POST http://localhost:8000/api/v1/scan/findings \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123"}'
```

### Example: Prioritize Pre-Parsed Findings

```bash
curl -X POST http://localhost:8000/api/v1/prioritize \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [
      {"scanner": "Fickling", "scanner_severity": "CRITICAL", "title": "Malicious pickle", "description": "os.system call", "category": "Model Artifact"}
    ],
    "model": "gpt-4o"
  }'
```

### Example: Upload Scanner Output

```bash
curl -X POST http://localhost:8000/api/v1/upload-and-scan \
  -F "file=@semgrep.json" \
  -F "scanner=semgrep"
```

---

## 10. How to Use Azure AI Foundry Integration

### Prerequisites

```bash
pip install azure-ai-ml azure-identity
az login  # Authenticate locally
```

### Interactive Discovery

```bash
python scripts/azure_fetch.py \
  --subscription-id YOUR_SUB_ID \
  --resource-group YOUR_RG \
  --workspace-name YOUR_WORKSPACE \
  --discover
```

This lists all models in a formatted table and prompts you to select which ones to download for scanning.

### Headless (CI/CD) Modes

```bash
# Download every model
python main.py --target . \
  --azure-subscription-id X --azure-resource-group Y --azure-workspace-name Z \
  --azure-scan-all

# Filter by name pattern
python main.py --target . \
  --azure-subscription-id X --azure-resource-group Y --azure-workspace-name Z \
  --azure-filter-name "bert*"

# Filter by tag
python main.py --target . \
  --azure-subscription-id X --azure-resource-group Y --azure-workspace-name Z \
  --azure-filter-tag "env=production"

# Filter by model type
python main.py --target . \
  --azure-subscription-id X --azure-resource-group Y --azure-workspace-name Z \
  --azure-filter-type "mlflow_model"
```

### Legacy Single-Model Mode

```bash
python main.py --target . \
  --azure-subscription-id X --azure-resource-group Y --azure-workspace-name Z \
  --azure-model-name my-bert-model --azure-model-version 2
```

Models are downloaded to `./azure_models_cache/<model_name>/v<version>/` and then scanned.

---

## 11. How to Configure AI Prioritization (OpenAI)

### Set API Key

```bash
# Environment variable (recommended)
export OPENAI_API_KEY=sk-your-key-here

# Or pass directly
python main.py --target . --prioritize --model gpt-4o

# Or for the API server
OPENAI_API_KEY=sk-your-key uvicorn api.app:app --host 0.0.0.0 --port 8000
```

### Change the Model

```bash
python main.py --target . --prioritize --model gpt-4o-mini  # Cheaper
python main.py --target . --prioritize --model gpt-4o       # Default
```

For the API, set `OPENAI_MODEL` environment variable or pass `"model"` in request bodies.

### What the AI Returns

For each finding, OpenAI provides:
- `priority_rank` (1 = most critical)
- `ai_severity` (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL)
- `cvss_estimate` (0.0-10.0)
- `exploit_likelihood` (CONFIRMED/HIGH/MEDIUM/LOW/THEORETICAL)
- `blast_radius` (FULL_SYSTEM/SERVICE/COMPONENT/MINIMAL)
- `attack_vector` (description of how it could be exploited)
- `remediation` (specific actionable fix)
- `justification` (why this ranking)

### Standalone Prioritization

```bash
# Just prioritize existing scan results
python scripts/prioritize_vulnerabilities.py \
  --results-dir sentinel-results/20260324-180522 \
  --model gpt-4o \
  -o prioritized.json

# Dry run (see findings without API call)
python scripts/prioritize_vulnerabilities.py \
  --safety-results safety_results.json \
  --dry-run
```

---

## 12. How to Generate the PDF Report

### Quick Path (Full Pipeline)

```bash
# Generate fixtures + run all scans + generate PDF
make report-pdf
```

### Custom Path

```bash
python scripts/generate-pdf-report.py \
  --scan-fixtures \
  --target ./your-project \
  --configs-dir ./configs \
  --fixtures-dir ./tests/fixtures \
  -o my-report.pdf
```

### From Existing Results

```bash
python scripts/generate-pdf-report.py \
  --results-dir sentinel-results/20260324-180522 \
  -o report.pdf
```

### What the PDF Contains

- Color-coded executive summary
- Per-layer tool status tables (installed/findings/details)
- Semgrep findings with severity, file, line, description
- Model scanner accuracy table (per-scanner pass/fail/skip rates)
- Per-file detailed results for every fixture vs. every scanner
- Dependency CVE table
- SBOM component breakdown (package, version, type, PURL)
- Fixture inventory with malicious/safe classification
- Detailed raw findings from each scanner

---

## 13. How to Run Tests

### Ground Truth Validation

```bash
# Generate fixtures and test all installed scanners
make test

# With verbose per-file output
make test-verbose

# Or directly
python tests/fixtures/generate-fixtures.py
bash tests/test-scanners.sh --verbose
```

The test suite validates that:
- Every malicious fixture is correctly flagged (no false negatives)
- Every safe fixture is correctly cleared (no false positives)

### Scanner Validation with Fuzzing

```bash
make validate-scanners
```

Requires Pickle-Fuzzer (`cargo install pickle-fuzzer`). Generates 50 adversarial pickle files and measures each scanner's detection rate.

### Fixture Regeneration

```bash
# Pickle-focused (tests/fixtures/)
make generate-fixtures
# or
python tests/fixtures/generate-fixtures.py

# Multi-format (root directory or custom output)
python generate_all_fixtures.py
python generate_all_fixtures.py -o ./custom-dir
```

---

## 14. How to Change/Add Test Fixtures

### Add a New Malicious Fixture

Edit `tests/fixtures/generate-fixtures.py`:

```python
def make_malicious_my_exploit():
    class Exploit:
        def __reduce__(self):
            return (os.system, ("echo my-exploit",))

    path = os.path.join(FIXTURES_DIR, "malicious-my-exploit.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-my-exploit.pkl",
             malicious=True,
             category="pickle-exploit",
             description="My custom exploit technique",
             techniques=["__reduce__", "GLOBAL", "os.system"])
```

Then call it from `main()` and re-run:
```bash
python tests/fixtures/generate-fixtures.py
make test
```

### Add a New Safe Fixture

Same pattern but with `malicious=False`.

### Add a Non-Pickle Format

Edit `generate_all_fixtures.py` and add a new `gen_<format>()` function.

---

## 15. How to Deploy with Terraform (VM-Based)

This deploys a single Azure VM running Docker. Simpler but less scalable.

### Prerequisites

- Azure CLI (`az`) authenticated
- Terraform >= 1.5
- Your OpenAI API key

### Steps

```bash
cd terraform

# 1. Create tfvars
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars:
#   openai_api_key = "sk-your-real-key"
#   allowed_ip = "YOUR_IP/32"  # Restrict access to your IP

# 2. Initialize
terraform init

# 3. Preview
terraform plan

# 4. Deploy
terraform apply

# 5. Wait ~5 minutes for cloud-init to complete, then:
curl http://<vm_public_ip>:8000/api/v1/health
```

### What Gets Created

- Resource group `rg-ai-sentinel`
- VNet + subnet with locked-down NSG (only port 8000 allowed)
- Ubuntu 22.04 VM (`Standard_B2s` by default)
- Cloud-init: installs Docker, clones repo, builds image, runs container, disables SSH

### Destroy

```bash
terraform destroy
```

---

## 16. How to Deploy with Terraform (Container Apps)

This is the production-grade deployment. Uses Azure Container Apps for autoscaling, ACR for image storage, Key Vault for secrets.

### Prerequisites

- Azure CLI, Terraform, Docker Desktop
- Your OpenAI API key

### Using deploy.ps1 (Recommended)

```powershell
# Preview only
.\infra\deploy.ps1 -OpenAIApiKey "sk-your-key" -PlanOnly

# Full deploy
.\infra\deploy.ps1 -OpenAIApiKey "sk-your-key"

# Tear down everything
.\infra\deploy.ps1 -OpenAIApiKey "sk-your-key" -Destroy
```

### Manual Steps

```bash
cd infra

# 1. Create tfvars
cp terraform.tfvars.example terraform.tfvars
# Edit with your values

# 2. Initialize
terraform init

# 3. Deploy infrastructure (ACR first)
terraform apply -target=azurerm_container_registry.acr -var "openai_api_key=sk-your-key" -auto-approve

# 4. Build and push Docker image
ACR_SERVER=$(terraform output -raw acr_login_server)
az acr login --name ${ACR_SERVER%.azurecr.io}
docker build -t $ACR_SERVER/ai-sentinel-api:latest ..
docker push $ACR_SERVER/ai-sentinel-api:latest

# 5. Deploy everything
terraform apply -var "openai_api_key=sk-your-key" -auto-approve

# 6. Get the URL
terraform output api_url
```

### What Gets Created

- Resource Group, Log Analytics, ACR, Managed Identity
- Key Vault (stores OpenAI key), Storage Account (model uploads + scan results)
- Container App Environment + Container App (with health probes, autoscaling 0-3 replicas)
- External HTTPS ingress

---

## 17. How to Tweak Terraform Scripts

### Change VM Size (terraform/)

Edit `terraform/terraform.tfvars`:
```hcl
vm_size = "Standard_B4ms"  # 4 vCPU, 16GB RAM
```

### Change Container Resources (infra/)

Edit `infra/terraform.tfvars` or pass variables:
```hcl
container_cpu    = 2.0
container_memory = "4Gi"
max_replicas     = 5
min_replicas     = 1
```

### Change Region

```hcl
location = "westeurope"  # or any Azure region
```

### Restrict API Access

In `terraform/terraform.tfvars`:
```hcl
allowed_ip = "203.0.113.10/32"  # Your IP only
```

In `infra/`, modify the ingress section in `main.tf` to add IP restrictions.

### Add a New Azure Resource

1. Add the resource block to `main.tf`
2. Add any new variables to `variables.tf`
3. Add outputs to `outputs.tf`
4. Run `terraform plan` to preview

### Change the Docker Image Tag

```hcl
container_image_tag = "v1.2.0"  # Instead of "latest"
```

### Use a Different Container Registry

Edit the `registry` block in the Container App resource and the `image` field.

### Add Environment Variables

In `infra/main.tf`, add to the container `env` blocks:
```hcl
env {
  name  = "MY_CUSTOM_VAR"
  value = "my-value"
}
```

### Enable HTTPS Only (terraform/)

The VM deployment uses HTTP. To add HTTPS:
1. Add an Azure Application Gateway or use a reverse proxy (nginx/caddy)
2. Or switch to the Container Apps deployment which provides HTTPS automatically

---

## 18. How to Deploy with Docker (Local)

### Build

```bash
docker build -t ai-sentinel .
```

### Run

```bash
docker run -d \
  --name ai-sentinel \
  -p 8000:8000 \
  -e OPENAI_API_KEY=sk-your-key \
  -e OPENAI_MODEL=gpt-4o \
  ai-sentinel
```

### Test

```bash
curl http://localhost:8000/api/v1/health
# Open http://localhost:8000/docs for Swagger UI
```

### Mount a Directory for Scanning

```bash
docker run -d \
  -p 8000:8000 \
  -e OPENAI_API_KEY=sk-your-key \
  -v /path/to/your/project:/scan-target \
  ai-sentinel
```

Then scan via API:
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target_dir": "/scan-target"}'
```

---

## 19. How to Configure Each Scanner

### Semgrep

Edit `configs/semgrep.yml` to add/modify rules. Each rule needs:
```yaml
- id: my-rule-id
  patterns:
    - pattern: dangerous_function(...)
  message: "Why this is bad"
  languages: [python]
  severity: ERROR  # ERROR, WARNING, INFO
  metadata:
    cwe: "CWE-XXX"
```

### Promptfoo

Edit `configs/promptfoo.yml`:
1. Change `providers` to your actual LLM provider
2. Add test cases under `tests:`
3. Each test has `vars.message` (input) and `assert` (expectations)
4. Assert types: `contains`, `not-contains`, `llm-rubric`, `similar`

### Veritensor

Edit `configs/veritensor.yml`:
- `scan.severity_threshold`: Minimum severity to fail on (CRITICAL, HIGH, etc.)
- `license.blocked/warn`: License SPDX IDs to block or warn about
- `pickle.allowed_modules/blocked_modules`: Module allowlists for pickle scanning
- `trusted_repos`: Hugging Face repo patterns for hash verification

### SafeDep vet

Edit `configs/vet-policy.yml`. Each policy uses CEL expressions:
```yaml
- name: my-policy
  description: "What it does"
  action: deny  # or warn
  expression: >
    vulns.critical.exists(v, true)
```

Available fields: `vulns.critical`, `vulns.high`, `pkg.malware`, `scorecard.score`, `pkg.last_release_age_days`, `pkg.license`, `pkg.deprecated`.

### Dependency-Track

1. Copy `configs/dependency-track.env.example` to `dependency-track.env`
2. Fill in `DT_URL`, `DT_API_KEY`, `DT_PROJECT_UUID`
3. The SBOM upload happens automatically in `scan-sbom.sh`

### CodeQL

No configuration file needed. It uses the standard `python-security-extended.qls` query suite. To change:
Edit the `codeql database analyze` command in `scan-code.sh` or `sentinel-scan.py`.

### OSV-Scanner

No configuration needed. Automatically scans lockfiles (requirements.txt, package-lock.json, go.sum, etc.).

---

## 20. How to Add a New Scanner Tool

Follow the checklist in `docs/ADDING-TOOLS.md`:

1. **Write a scan script** in `scripts/scan-<layer>.sh` (or add to existing one)
2. **Add installation** to `scripts/install.sh`
3. **Add output parsing** to `scripts/report.sh`
4. **Add to `check-tools`** in `Makefile`
5. **Add to CI** in the appropriate `.github/workflows/*.yml`
6. **Add config** to `configs/` if needed

### For the Python Engine

Add a scanner class in `scripts/sentinel-scan.py`:

```python
class MyToolAdapter(CLIAdapter):
    name = "MyTool"
    category = "Model Artifact"  # or Code SAST, etc.

    def scan(self, target_dir, config_dir=None):
        findings = []
        rc, out, err = self.run_cmd("mytool", ["scan", target_dir])
        if rc == -1:
            return findings
        # Parse output and create Finding objects
        findings.append(Finding(self.name, self.category, "HIGH",
                                "Finding title", "Description", "file.py"))
        return findings
```

Then add it to `SentinelEngine.__init__()`:
```python
self.scanners = [
    ...,
    MyToolAdapter(),
]
```

---

## 21. How CI/CD Works

### On Pull Request

`pr-scan.yml` runs three parallel jobs in ~2 minutes:
- Semgrep SAST (uploads SARIF to GitHub Security tab)
- Model scanning (if model files exist)
- OSV-Scanner dependency check

### On Push to Main

`full-scan.yml` runs all 6 layers in parallel (~10 minutes total):
- Each layer uploads artifacts
- Final `report` job downloads all artifacts and generates `REPORT.md`
- Results are available as workflow artifacts

### Nightly (2 AM UTC)

`nightly-deep.yml` runs expensive/slow tools:
- Full CodeQL analysis
- BAIT behavioral backdoor detection
- Pickle-Fuzzer scanner validation with detection rates

### Required Secrets

Set these in GitHub repository settings > Secrets:
- `OPENAI_API_KEY` -- For Promptfoo and AI prioritization
- `DT_URL`, `DT_API_KEY`, `DT_PROJECT_UUID` -- For Dependency-Track upload (optional)

---

## 22. How to Use the Test Goat Project

The test goat is a deliberately vulnerable project designed to exercise every scanning layer.

### Generate It

```bash
python scripts/generate_test_goat.py
```

### Scan It

```bash
# Full pipeline with AI prioritization
python main.py --target ./sentinel-test-goat --prioritize

# Or via Makefile
make scan TARGET=./sentinel-test-goat

# Or specific layers
make scan-code TARGET=./sentinel-test-goat
make scan-models TARGET=./sentinel-test-goat
```

### What Should Be Found

| Layer | Expected Findings |
|-------|------------------|
| Code SAST | Hardcoded API keys, os.system injection, unsafe yaml.load |
| Agent Architecture | Insecure MCP config (no HITL, no sandboxing) |
| Model Artifacts | Pickle RCE in malicious_model.pkl |
| Prompt Testing | Jailbreak and PII leakage test failures |
| Dependencies | CVEs in requests 2.19.0, urllib3 1.24; typosquats |
| SBOM | Missing metadata on undocumented_model.h5 |

---

## 23. Environment Variables Reference

| Variable | Purpose | Where Used |
|----------|---------|-----------|
| `OPENAI_API_KEY` | OpenAI API key for prioritization | main.py, api/app.py, prioritize_vulnerabilities.py |
| `OPENAI_MODEL` | OpenAI model name | api/app.py, terraform/ |
| `TARGET` | Directory to scan | Makefile, all scan scripts |
| `RESULTS_DIR` | Output directory for results | Makefile, all scan scripts |
| `CONFIGS_DIR` | Config directory path | Makefile, scan scripts |
| `DT_URL` | Dependency-Track server URL | scan-sbom.sh |
| `DT_API_KEY` | Dependency-Track API key | scan-sbom.sh |
| `DT_PROJECT_UUID` | Dependency-Track project UUID | scan-sbom.sh |
| `VET_DISABLE_TELEMETRY` | Disable SafeDep vet telemetry | scan-deps.sh |
| `AZURE_STORAGE_ACCOUNT` | Azure storage account name | api/app.py (Container Apps) |
| `AZURE_CLIENT_ID` | Managed identity client ID | api/app.py (Container Apps) |

---

## 24. Makefile Targets Reference

| Target | Description |
|--------|-------------|
| `help` | Show all targets with descriptions |
| `install` | Install all tools (full 16+ stack) |
| `install-minimal` | Install minimum viable tools (5-tool stack) |
| `scan` | Run full scan (all 6 layers) |
| `scan-fast` | Run fast PR-level scan (~2 min) |
| `scan-code` | Layer 1: Code SAST |
| `scan-models` | Layer 2: Model artifact scanning |
| `scan-prompts` | Layer 3: Prompt regression testing |
| `scan-agents` | Layer 1b: Agent architecture analysis |
| `scan-deps` | Layer 4: Dependency vulnerability scanning |
| `scan-sbom` | Layer 5: SBOM generation and governance |
| `validate-scanners` | Test scanners with adversarial samples |
| `check-tools` | Show which tools are installed |
| `report` | Generate unified markdown report |
| `report-pdf` | Full 6-layer scan + fixture validation + PDF |
| `generate-fixtures` | Regenerate test model fixtures |
| `test` | Test scanners against ground truth fixtures |
| `test-verbose` | Test with per-file details |
| `clean` | Remove all scan results |
| `prioritize` | AI-prioritize vulnerabilities using OpenAI |

---

## 25. API Endpoints Reference

### `GET /api/v1/health`
Health check. Returns `{status, version, timestamp, openai_configured}`.

### `POST /api/v1/scan`
Start a background scan. Body: `{target_dir, config_dir?, prioritize?, model?}`. Returns `{scan_id, status}`.

### `POST /api/v1/scan/progress`
Poll scan progress. Body: `{scan_id}`. Returns `{status, progress_percent, scanners_completed, total_scanners, current_scanner}`.

### `POST /api/v1/scan/summary`
Get severity counts. Body: `{scan_id}`. Returns `{severity_counts: {Critical, High, Medium, Low}, total_vulnerabilities}`.

### `POST /api/v1/scan/findings`
Get all findings with AI enrichment. Body: `{scan_id}`. Returns findings with: `id`, `severity`, `category` (one of 5 canonical categories), `title`, `description`, `artifact`, `scanner`, `line`, `indicators`, and optional AI fields (`priority_rank`, `cvss_estimate`, `exploit_likelihood`, `blast_radius`, `attack_vector`, `remediation`, `justification`).

### `POST /api/v1/scans`
List all scans. Returns `{scans: [{scan_id, status, progress_percent, target_dir, started_at, completed_at}]}`.

### `POST /api/v1/prioritize`
Prioritize pre-parsed findings. Body: `{findings: [...], model?}`. Returns AI-prioritized results.

### `POST /api/v1/scan-results`
Parse raw scanner output and prioritize. Body: `{scanner: "semgrep"|"fickling"|"modelscan"|"picklescan"|"osv-scanner", results: {...}, model?}`.

### `POST /api/v1/upload-and-scan`
Upload a scanner output file. Multipart form: `file` (the file), `scanner` (name or "auto"), `model`. Auto-detects format from filename.

---

## 26. Troubleshooting

### "ModuleNotFoundError: No module named 'modelscan'"
```bash
pip install modelscan
```

### "semgrep: command not found"
Semgrep is installed separately from the main requirements to avoid version conflicts:
```bash
pip install semgrep
```

### "Azure authentication failed"
```bash
az login                          # Interactive login
az account set --subscription X   # Set correct subscription
```

### "OpenAI returned no content / refusal"
The OpenAI safety system sometimes refuses to analyze security findings. The system prompt includes context about this being an authorized security audit. If it persists, try a different model or reduce the number of findings per chunk.

### "Terraform state lock"
```bash
terraform force-unlock <lock-id>
```

### "Docker build fails on Windows"
Ensure Docker Desktop is running in Linux container mode. The Dockerfile uses Linux-based images.

### "Pickle-Fuzzer install fails"
Requires Rust toolchain:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install pickle-fuzzer
```

### Scans find nothing
- Check `make check-tools` to see what's installed
- Verify the target directory contains the expected files
- Model scanners require model files (.pkl, .pt, .h5, etc.) to be present

### Container App not responding
1. Check health: `curl https://<app-url>/api/v1/health`
2. Check logs: `az containerapp logs show --name ca-aisentinel-prod --resource-group rg-aisentinel-prod`
3. Verify the image was pushed: `az acr repository list --name <acr-name>`

---

*This document was generated from a complete reading of every file in the repository.*

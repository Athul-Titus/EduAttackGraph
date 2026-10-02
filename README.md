# LLM-EduAttackGraph

> **A research-grounded, human-in-the-loop security vulnerability analysis platform for educational web applications.**
> This project uses the LLM-EduAttackGraph paper as its foundational base and intentionally extends it. See [Improvements Over the Base Paper](#improvements-over-the-base-paper) for details.

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-blue)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## ⚠️ Authorized Use Only

This tool is designed exclusively for:
- **localhost** and controlled laboratory environments
- **Intentionally vulnerable** applications (DVWA, WebGoat, Metasploitable, etc.)
- **Test environments** under your ownership
- **Explicitly authorized targets** with written permission

**This tool does NOT perform autonomous exploitation.** It is a decision-support system for human security analysts.

---

## Research Basis

This project implements and extends the concepts from:

> *"LLM-Assisted Security Vulnerability Analysis for Educational Websites: Risk Identification via LLM-EduAttackGraph"*  
> Chao Liu, Jiaxing Liu, Boxi Chen, Daxin Zhu, Ching-Chun Chang, Chin-Chen Chang  
> IEEE Internet of Things Journal, Vol. 13, No. 2, 15 January 2026  
> DOI: 10.1109/JIOT.2025.3631562

The paper introduces LLM-EduAttackGraph, a two-stage system:
1. **Website Fingerprinting** — TCP/IP probing, service identification, web fingerprinting
2. **LLM-Driven Penetration Path Inference** — RAG with BGE embeddings + FAISS + LLM inference

---

## Improvements Over the Base Paper

Several design choices in this implementation **intentionally diverge** from the paper. These are deliberate improvements, not bugs.

| Aspect | Paper (Liu et al., 2026) | This Implementation | Rationale |
|--------|--------------------------|---------------------|-----------|
| **Embedding model** | `bge-small-zh` (Chinese-only, 512-dim) | `BAAI/bge-small-en-v1.5` (English, 384-dim) | Paper's model is Chinese-only; English model covers the Awesome-POC corpus which is bilingual but predominantly used in English-language contexts. Model is configurable — swap to `bge-m3` for full multilingual coverage. |
| **LLM provider** | DeepSeek (single vendor, paid API) | Groq (primary) + NVIDIA NIM + OpenAI + DeepSeek (all supported) | Multi-provider removes single-vendor lock-in. Groq's free tier enables zero-cost research use. Fallback chain: Groq → NVIDIA NIM → OpenAI → DeepSeek. |
| **Evidence provenance** | Conceptual only ("human-in-the-loop") | Formal `EvidenceType` enum: `OBSERVED` / `RETRIEVED` / `INFERRED` / `VALIDATED` | Every output is tagged at the field level. Findings cannot be promoted without explicit human action. Audit trail is immutable. |
| **Validation workflow** | Paper describes it conceptually; no FSM defined | Formal state machine: `potential → pending_review → validated / rejected / needs_more_evidence` | Prevents LLM outputs from being treated as confirmed findings. Each state transition is recorded with analyst name, timestamp, and comment. |
| **Audit trail** | Not specified | Immutable `audit_events` table; every scan, state change, and admin action is logged | Traceability for responsible disclosure and reproducibility of research. |
| **Interface** | Research script / command-line tool | Full React/TypeScript web dashboard with admin panel, target management, scan orchestration, HITL review UI, CSV/PDF export, plain-English explainers | The paper has no UI. The dashboard makes the system usable by analysts without direct DB access. |
| **Target safety** | Allowlist mentioned conceptually | `AuthorizationManager` with three modes (`allowlist`, `lab`, `localhost_only`), SSRF protection, shell-injection filtering on hostnames, DB-backed authorized-target registry managed via admin UI | Defense-in-depth rather than a single env-var check. |
| **Similarity threshold** | 0.6 (stated in paper) | 0.6 (default, configurable), with `>=` comparison enforced and unit-tested | Paper does not state the comparison direction. `>=` is used so that fingerprints scoring exactly 0.6 are not silently dropped. |

---

## Architecture

```
AUTHORIZED TARGET
       │
       ▼
┌─────────────────────┐
│  Fingerprinting      │  Algorithm 1
│  - TCP Port Scan     │
│  - Service ID        │
│  - Web Fingerprint   │
└──────────┬──────────┘
           │ Structured Fingerprint (OBSERVED)
           ▼
┌─────────────────────┐
│  BGE Embedding      │ ◄── BAAI/bge-small-en-v1.5 (configurable)
│  normalize_L2=True  │     Same model used for index build AND query
└──────────┬──────────┘
           │ L2-normalized query vector
           ▼
┌─────────────────────┐
│  FAISS IndexFlatIP  │ ◄── Awesome-POC knowledge base (961 POCs)
│  (cosine sim via    │     Vectors L2-normalized at insert AND query
│   normalized IP)    │
└──────────┬──────────┘
           │ Top-K results (RETRIEVED)
           ▼
┌─────────────────────┐
│  Similarity Filter  │
│  max_sim >= 0.60    │ (>= not >; paper threshold)
└──────────┬──────────┘
           │ Relevant historical evidence
           ▼
┌─────────────────────┐     Prompt = Φ(query)
│  RAG Prompt Build   │     ⊕ Ψ(best_match)
│  (untrusted Ψ is    │     ⊕ Γ(template)
│   sandboxed/labeled)│     Γ appears BEFORE Ψ
└──────────┬──────────┘
           │ Structured prompt
           ▼
┌─────────────────────┐
│  LLM Inference      │ ◄── Groq (primary) / NVIDIA NIM / OpenAI
│  (INFERRED output)  │     validation_required: true enforced
└──────────┬──────────┘
           │ Potential vulnerability (INFERRED — not confirmed)
           ▼
┌─────────────────────┐
│  Human Validation   │ ◄── HITL state machine
│  HITL FSM           │     potential → pending_review
└──────────┬──────────┘     → validated / rejected / needs_more_evidence
           │
           ▼
┌─────────────────────┐
│  Security Report    │ ◄── JSON + Markdown + PDF-ready HTML
└─────────────────────┘
```

### Evidence Classification
Every field in every output is clearly tagged:
- **OBSERVED** — Directly obtained from TCP/HTTP reconnaissance
- **RETRIEVED** — From the Awesome-POC knowledge base (RAG result)
- **INFERRED** — Generated by LLM analysis (not confirmed)
- **VALIDATED** — Reviewed and accepted by a human analyst

---

## Features

- ✅ Controlled TCP port scanning (Python-native)
- ✅ Service and version identification via banner grabbing
- ✅ HTTP/HTTPS web fingerprinting (headers, CMS detection)
- ✅ BGE multilingual embeddings (BAAI/bge-small-en-v1.5 default)
- ✅ FAISS vector database with enforced L2 normalization + cosine similarity
- ✅ Configurable similarity threshold (default: 0.6, paper value)
- ✅ Awesome-POC knowledge base (961 educational CVE POCs)
- ✅ Multi-provider LLM: Groq / NVIDIA NIM / OpenAI / DeepSeek / mock
- ✅ Human-in-the-loop validation state machine
- ✅ Full evidence provenance and immutable audit trail
- ✅ Structured security report generation (JSON + Markdown + HTML/PDF)
- ✅ Demo mode (no external targets needed)
- ✅ Admin UI — manage authorized targets via web dashboard
- ✅ FastAPI backend with OpenAPI docs at `/api/docs`
- ✅ React/TypeScript/Vite frontend dashboard
- ✅ Plain-English vulnerability explanations for non-security audiences

---

## Technology Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| Backend | Python 3.11+, FastAPI | Async, `asynccontextmanager` lifespan |
| ORM | SQLAlchemy 2.0 (async) | AsyncSession, aiosqlite driver |
| Database | **SQLite** (default and current) | Runs without any setup. See [Database](#database) note. |
| Embeddings | sentence-transformers, `BAAI/bge-small-en-v1.5` | Configurable via `EMBEDDING_MODEL` |
| Vector DB | FAISS (`IndexFlatIP` + L2 normalization) | Enforced at both insert and query time |
| LLM | Groq (primary), NVIDIA NIM, OpenAI, DeepSeek | Configurable via `LLM_PROVIDER` |
| Frontend | React 18, TypeScript, Vite | Dark cybersecurity design system |
| Auth | PBKDF2-HMAC-SHA256 passwords, JWT Bearer tokens | Admin auto-seeded on startup |
| Logging | structlog | Structured JSON logs |
| Config | pydantic-settings | All config from `.env` |
| Containers | Docker, docker-compose | `docker-compose up -d` for full deploy |

### Database

> **Current state:** SQLite with `create_tables()` on startup — no Alembic migrations.
>
> The database schema is created automatically at first startup. There are no migration files. If you change models, you must drop and recreate the database (acceptable for a research/personal project).
>
> **Roadmap:** Alembic migration support is planned (see [Future Work](#future-work)). PostgreSQL is supported via the `DATABASE_URL` env var — switch the driver to `postgresql+asyncpg://...` and it will work without code changes.

---

## Six Vulnerability Categories (from paper)

| Code | Category | Paper Prevalence |
|------|----------|-----------------|
| O1 | Remote Code Execution (RCE) | 3.85% |
| O2 | SQL Injection | 4.05% |
| O3 | Weak Password | 55.61% |
| O4 | Unauthorized Access | 28.20% |
| O5 | Token Tampering | 0.73% |
| O6 | Sensitive Information Disclosure | 5.93% |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (for full deployment)

### 1. Clone and Configure

```bash
git clone <this-repo>
cd llm-edu-attackgraph
cp .env.example .env
# Edit .env: set GROQ_API_KEY and LLM_PROVIDER=groq (or keep mock for testing)
```

### 2. Backend Setup

```bash
cd backend
pip install -r requirements.txt

# Tables are created automatically at first startup — no migration step needed
uvicorn app.main:app --reload --port 8000
```

### 3. Build the FAISS Knowledge Base Index (one-time, ~10 min)

```bash
# From the project root (llm-edu-attackgraph/)
python scripts/build_faiss_index.py
# Clones Awesome-POC, embeds ~961 vulnerability entries, saves to ./faiss_index/
```

### 4. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 5. Docker (Full Deployment)

```bash
docker-compose up -d
# Backend: http://localhost:8000
# Frontend: http://localhost:80
# API docs: http://localhost:8000/api/docs
```

### 6. Admin Login

Default admin credentials (seeded automatically on first startup):
- Email: `titusathul8@gmail.com`
- Password: set in your `.env` as `SECRET_KEY` (or contact the project owner)

Use the **Admin Login** button in the sidebar to manage authorized scan targets.

---

## LLM Provider Configuration

| Provider | Status | Notes |
|----------|--------|-------|
| `groq` | ✅ **Tested, active (default)** | Free tier available. Get key at console.groq.com |
| `nvidia` | ✅ Tested, active (fallback) | Free credits. Get key at build.nvidia.com |
| `openai` | ✅ Tested | Paid. `gpt-4o-mini` is cost-effective |
| `deepseek` | ⚠️ Supported, not tested | Paid API. Paper's original LLM |
| `mock` | ✅ Works without any API key | For testing/CI only — synthetic responses |

Set in `.env`:
```env
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...
GROQ_MODEL=qwen/qwen3.8-27b
```

---

## Configuration Reference

See [.env.example](.env.example) for all options. Key settings:

```env
# Embedding model (must match what was used to build the FAISS index)
EMBEDDING_MODEL=BAAI/bge-small-en-v1.5

# RAG thresholds (paper values)
SIMILARITY_THRESHOLD=0.60
TOP_K=5

# LLM — Groq is the recommended default (free tier)
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...

# Authorization mode
AUTHORIZED_TARGET_MODE=localhost_only   # safest default
```

---

## Running Tests

```bash
cd backend
pip install pytest

# Task 4 unit tests: FAISS cosine similarity, threshold correctness, prompt safety
pytest tests/unit/test_faiss_similarity.py -v

# E2E live test (requires running backend)
python scripts/test_live_e2e.py
```

---

## Demo Mode

Run the system without any external scanning:

```env
# In .env:
APP_ENV=demo
```

The system will use a pre-built RuoYi CMS fingerprint sample and synthetic knowledge base documents. All outputs are labeled **[DEMO]**.

---

## Limitations

1. **Logical/business-flow vulnerabilities** are not supported (paper acknowledges this); see [Future Work](#future-work) for a proposed detection approach
2. The tool **does not execute exploit payloads** — it provides analysis only
3. LLM outputs are **INFERRED**, not confirmed findings — human review is mandatory
4. The paper's evaluation was on Chinese educational websites; this implementation has not independently reproduced those results
5. `bge-small-en-v1.5` is used instead of `bge-small-zh` (paper's model) — for better English coverage; swap via `EMBEDDING_MODEL` env var (rebuild FAISS index after changing models)
6. **No Alembic migrations** — schema is created with `create_tables()` at startup; model changes require manual DB reset

---

## Security Restrictions

- Only allowlisted/admin-authorized targets may be scanned
- SSRF protection: hostname is resolved to IP and checked against private ranges
- Shell-injection filtering on all hostname inputs
- LLM has no shell execution privileges
- Retrieved knowledge base content (Ψ) is labeled as untrusted in the prompt; template (Γ) always precedes it
- All scans, state changes, and admin actions are audit-logged

---

## Future Work

| Item | Priority | Notes |
|------|----------|-------|
| Alembic database migrations | Medium | Replace `create_tables()` with versioned migrations |
| JWT refresh tokens | Medium | Currently 24h expiry, no refresh endpoint |
| WebSocket/SSE scan progress | Medium | Replace 3s polling with push events |
| Logical flaw detection | Research | See design doc below |
| Chinese language BGE model | Low | Swap to `bge-small-zh` for original paper fidelity |
| DeepSeek integration | Low | Requires paid API budget |
| Attack graph visualization | Research | D3/Cytoscape.js attack path graph from validated findings |
| Distributed FAISS | Future | Paper mentions distributed retrieval as future work |

### Logical Vulnerability Detection (Design Proposal)

The paper explicitly states it does not support logical/business-flow vulnerabilities. A concrete detection approach using existing data:

**Approach:** Cross-finding inconsistency analysis using the audit trail and validated findings.

**Detection rule example:** If a `VALIDATED` finding confirms that endpoint `/admin/api` is vulnerable to `O4_UNAUTHORIZED` (unauthorized access), and a separate scan of the same target later fingerprints that endpoint as reachable without credentials — flag a `LOGICAL_INCONSISTENCY` event.

**Implementation path:**
1. After each scan completes, run a post-processing pass over all `VALIDATED` findings for the same target hostname
2. For each O4 (Unauthorized Access) validated finding, check if later scans still observe the endpoint open without auth evidence
3. Cross-reference O3 (Weak Password) findings against O5 (Token Tampering) — a token-tampering path implies a weak credential flow somewhere upstream
4. Surface these cross-finding signals as `LOGICAL_FLAG` evidence type in the findings table, requiring human review
5. No LLM inference needed for step 1-3 — pure rule-based over existing `VALIDATED` records

**Scope limit:** This is a post-hoc consistency checker, not a black-box logic tester. It does not discover new logical flaws; it surfaces contradictions in already-known validated findings.

Full design document: [docs/logical-vuln-detection-design.md](docs/logical-vuln-detection-design.md)

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Citation

If you use this implementation, please cite the original paper:

```bibtex
@article{liu2026llm,
  title={LLM-Assisted Security Vulnerability Analysis for Educational Websites: Risk Identification via LLM-EduAttackGraph},
  author={Liu, Chao and Liu, Jiaxing and Chen, Boxi and Zhu, Daxin and Chang, Ching-Chun and Chang, Chin-Chen},
  journal={IEEE Internet of Things Journal},
  volume={13},
  number={2},
  pages={3038--3054},
  year={2026},
  publisher={IEEE},
  doi={10.1109/JIOT.2025.3631562}
}
```

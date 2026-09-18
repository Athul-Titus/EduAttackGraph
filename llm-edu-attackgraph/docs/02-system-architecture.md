# System Architecture: LLM-EduAttackGraph

## Overview

The system implements the two-stage architecture described in the research paper, with additional components for the human-in-the-loop workflow, API layer, and frontend dashboard.

## Top-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (React/TypeScript/Vite)          │
│  Dashboard | Scans | Fingerprint | RAG | Analysis | Reports  │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTP/REST
┌────────────────────────────▼────────────────────────────────┐
│                   BACKEND API (FastAPI)                       │
│                   /api/v1/...                                 │
└────┬──────────────┬──────────────┬────────────────┬──────────┘
     │              │              │                │
     ▼              ▼              ▼                ▼
┌─────────┐  ┌──────────┐  ┌──────────┐   ┌──────────────┐
│Fingerprint│ │  RAG     │  │  LLM     │   │  Validation  │
│ Engine  │  │ Pipeline │  │ Inference│   │  & Reporting │
└────┬────┘  └────┬─────┘  └────┬─────┘   └──────┬───────┘
     │            │             │                 │
     ▼            ▼             ▼                 ▼
┌────────────────────────────────────────────────────────────┐
│              PostgreSQL (metadata, audit, findings)          │
└────────────────────────────────────────────────────────────┘
                  │
                  ▼ (separate)
┌────────────────────────────────────────────────────────────┐
│              FAISS Index (vector similarity search)          │
└────────────────────────────────────────────────────────────┘
```

## Stage 1: Fingerprinting Pipeline

```
AUTHORIZED TARGET (allowlisted only)
            │
            ▼
┌───────────────────────────┐
│    AuthorizationManager   │
│  (allowlist check + SSRF) │
└───────────┬───────────────┘
            │ Authorized
            ▼
┌───────────────────────────┐
│       PortScanner         │
│  Python socket / port-go  │
│  Returns: open_ports[]    │
└───────────┬───────────────┘
            │
     ┌──────┴──────┐
     │             │
     ▼             ▼
Per-port:    Non-HTTP ports:
┌──────────┐  record port + service
│ServiceID │
│server-go │
│or banner │
└────┬─────┘
     │ service ∈ {http, https}
     ▼
┌──────────────────┐
│ WebFingerprint   │
│ finger.exe or    │
│ HTTP analysis    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ FingerprintParser│
│ Structured JSON  │
└────────┬─────────┘
         │ Optional
         ▼
┌──────────────────┐
│  SparkAPI        │  ← Optional, from paper Algorithm 1
│  (adapter)       │    (pre-analysis, before RAG)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Structured       │
│ Fingerprint      │  → saved to PostgreSQL
│ (JSON)           │
└──────────────────┘
```

## Stage 2: RAG Pipeline (Offline)

```
OFFLINE PHASE:
Awesome-POC Repository
         │
         ▼
┌─────────────────┐
│  DocumentLoader │ ← parses markdown files
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  TextChunker    │ ← semantic chunking
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  BGEEmbedding   │ ← BAAI/bge-m3
│  Provider       │
└────────┬────────┘
         │ vectors
         ▼
┌─────────────────┐
│  FAISSVectorStore│ ← stored to disk
└─────────────────┘
```

## Stage 2: RAG Pipeline (Online)

```
ONLINE PHASE:
Structured Fingerprint
         │
         ▼ (text representation)
┌─────────────────┐
│ BGEEmbedding    │ ← SAME model as offline
│ (query embed)   │
└────────┬────────┘
         │ query_vector
         ▼
┌─────────────────┐
│ FAISSVectorStore│ ← top-K search
│ .search()       │
└────────┬────────┘
         │ [(chunk_id, score), ...]
         ▼
┌─────────────────┐
│ SimilarityEngine│ ← cosine similarity + threshold 0.6
└────────┬────────┘
         │ relevant_evidence[]
         ▼
┌─────────────────┐
│  RAGEngine      │
│  ContextBuilder │ ← Φ(T₂) ⊕ Ψ(T) ⊕ Γ
└────────┬────────┘
         │ structured prompt
         ▼
┌─────────────────┐
│  LLMProvider    │ ← DeepSeek / Groq / NVIDIA / OpenAI
└────────┬────────┘
         │ structured JSON response
         ▼
┌─────────────────┐
│  AnalysisEngine │ ← creates Finding (status: POTENTIAL)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  FindingManager │ → saved to PostgreSQL
└─────────────────┘
```

## Human Validation Workflow

```
Finding (POTENTIAL)
        │
        ▼
┌───────────────────────────────────────┐
│   Human Review Interface              │
│                                       │
│   Displays:                           │
│   - OBSERVED fingerprint              │
│   - RETRIEVED historical evidence     │
│   - Similarity score                  │
│   - Source document                   │
│   - INFERRED LLM analysis             │
│   - Severity + Remediation            │
│   - Uncertainty statement             │
└───────┬───────────────────────────────┘
        │
   ┌────┴────┐
   │         │         │
   ▼         ▼         ▼
VALIDATED  REJECTED  NEEDS_MORE
                     _EVIDENCE
   │
   ▼
ReportService → Security Report
```

## Component Separation

### Analysis System (Separate from Normal Application)

The analysis system operates as a **separate security advisor**:
1. Target application runs normally
2. Analysis system receives a URL/IP to analyze
3. Fingerprinting is a **read-only** external probe (no modification of target)
4. LLM analysis is performed offline against the fingerprint
5. No modifications are made to the target application

### Database Separation

```
PostgreSQL:
├── targets            (authorized target registry)
├── scans              (scan sessions)
├── ports              (open port records)
├── services           (service identification results)
├── fingerprints       (structured fingerprint data)
├── knowledge_documents (Awesome-POC ingestion records)
├── knowledge_chunks   (text chunks with metadata)
├── retrievals         (RAG retrieval records)
├── analyses           (LLM analysis results)
├── findings           (vulnerability findings)
├── validations        (human review records)
├── reports            (generated reports)
└── audit_events       (full audit trail)

FAISS Index (separate file):
├── vectors            (embedding vectors)
└── metadata.json      (FAISS ID → chunk ID mapping)
```

## Security Architecture

```
┌─────────────────────────────────────────────────────┐
│                Security Boundary                     │
│                                                     │
│  ┌─────────────────────┐                            │
│  │  AuthorizationMgr   │ ← allowlist enforcement    │
│  └─────────────────────┘                            │
│  ┌─────────────────────┐                            │
│  │  InputValidator     │ ← SSRF, injection          │
│  └─────────────────────┘                            │
│  ┌─────────────────────┐                            │
│  │  SecretManager      │ ← env vars, no hardcoding  │
│  └─────────────────────┘                            │
│  ┌─────────────────────┐                            │
│  │  LLMGuardrails      │ ← prompt injection protect │
│  └─────────────────────┘                            │
│  ┌─────────────────────┐                            │
│  │  AuditService       │ ← all events logged        │
│  └─────────────────────┘                            │
└─────────────────────────────────────────────────────┘
```

## Configuration Flow

```
.env file
    │
    ▼
pydantic-settings (Settings class)
    │
    ├── Database URL
    ├── FAISS paths
    ├── Embedding model
    ├── Similarity threshold
    ├── Top-K
    ├── LLM provider + API keys
    ├── Authorized target mode
    └── Target allowlist
```

# Changelog

All notable changes to LLM-EduAttackGraph are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Phase 0 — Research Analysis + Documentation

#### Added
- Complete research paper extraction and analysis
- `docs/00-project-overview.md` — Project overview
- `docs/01-research-specification.md` — Paper-grounded research specification
- `docs/02-system-architecture.md` — Full system architecture
- `docs/27-research-to-implementation.md` — Research component mapping
- `docs/28-known-gaps-and-assumptions.md` — Documented ambiguities
- `.env.example` — Full configuration reference
- `README.md` — Project README with research citation
- `CHANGELOG.md` — This file
- Initial project directory structure

#### Key Research Findings Documented
- Two-stage architecture: Fingerprinting → RAG Pipeline
- Algorithm 1 (Fingerprinting): port-go.exe → server-go.exe → finger.exe → spark-api
- Algorithm 2 (RAG): Awesome-POC → chunk → bge-small-zh → FAISS → cosine_sim >= 0.6 → DeepSeek
- Prompt formula: Φ(T₂) ⊕ Ψ(T) ⊕ Γ
- Six vulnerability categories: O1-O6
- Threshold: 0.6 (empirically calibrated, range 0.5–0.7)
- Accuracy: 98.89% on 90-sample test set (paper's result, not reproduced here)

#### Implementation Decisions Documented
- GAP-001: spark-api treated as optional, isolated from Stage 2
- GAP-002: Python-native fingerprinting with .exe adapter interfaces
- GAP-003: HTTP header analysis as "passive monitoring"
- GAP-004: Threshold does not confirm vulnerabilities (INFERRED label)
- GAP-005: bge-m3 (multilingual) as default instead of bge-small-zh
- GAP-006: Chunk size 512 tokens (not specified in paper)
- GAP-007: Top-K=5 (Algorithm 2 uses top-1, extended to top-K for richer context)
- GAP-008: JSON format internally, CSV export for compatibility
- GAP-009: No performance claims without independent evaluation
- GAP-010: Logical vulnerabilities not supported (per paper)

---

## [0.1.0] — Phase 1: Repository Foundation

*To be completed*

### Added
- Project skeleton with all directories
- `backend/requirements.txt`
- `backend/Dockerfile`
- `frontend/package.json`
- `docker-compose.yml`
- `Makefile`
- `.gitignore`

---

## [0.2.0] — Phase 2: Backend Foundation

*To be completed*

### Added
- FastAPI application (`backend/app/main.py`)
- Configuration management (`backend/app/config.py`)
- Database models (SQLAlchemy)
- Alembic migrations
- Structured logging
- Health check endpoint

---

## [0.3.0] — Phase 3: Fingerprinting Engine

*To be completed*

### Added
- `PortScanner` (Python socket-based)
- `ServiceIdentifier` (banner grabbing)
- `WebFingerprintProvider` (HTTP analysis)
- `FingerprintEngine` orchestrator
- `StructuredFingerprint` model
- Authorization manager with allowlist

---

## [0.4.0] — Phase 4: Knowledge Base Ingestion

*To be completed*

### Added
- `DocumentLoader` for Awesome-POC markdown files
- `TextChunker` (512 token chunks, 50 overlap)
- `MetadataExtractor`
- `KnowledgeBaseManager`
- Ingestion script (`scripts/ingest_knowledge_base.py`)

---

## [0.5.0] — Phase 5: BGE Embedding System

*To be completed*

### Added
- `BGEEmbeddingProvider` (BAAI/bge-m3)
- `EmbeddingProvider` interface
- Batch embedding support
- Model metadata storage

---

## [0.6.0] — Phase 6: FAISS Vector Store

*To be completed*

### Added
- `FAISSVectorStore` implementation
- Index build/save/load
- Metadata mapping (FAISS ID → chunk ID → document ID)
- FAISS index build script (`scripts/build_faiss_index.py`)

---

## [0.7.0] — Phase 7: RAG Pipeline

*To be completed*

### Added
- `SimilarityEngine` (cosine similarity, configurable threshold)
- `RetrievalEngine` (FAISS → top-K → threshold filter)
- `RAGEngine` with context builder
- Prompt construction: Φ(T₂) ⊕ Ψ(T) ⊕ Γ
- Versioned prompt templates

---

## [0.8.0] — Phase 8: LLM Integration

*To be completed*

### Added
- `LLMProvider` interface
- `DeepSeekProvider`
- `GroqProvider`
- `NVIDIAProvider`
- `OpenAIProvider`
- `MockProvider` (for testing)
- Output parser for structured JSON
- Guardrails (prompt injection protection)

---

## [0.9.0] — Phase 9: Human Validation

*To be completed*

### Added
- `ValidationService`
- Finding status FSM (POTENTIAL → PENDING_REVIEW → VALIDATED/REJECTED/NEEDS_MORE_EVIDENCE)
- Validation audit trail

---

## [0.10.0] — Phase 10: Reports

*To be completed*

### Added
- `ReportService`
- JSON and Markdown report formats
- Evidence provenance in reports

---

## [1.0.0] — Phase 11: Full Integration

*To be completed*

### Added
- All FastAPI endpoints
- React/TypeScript/Vite frontend
- Docker deployment
- Demo mode
- Complete test suite

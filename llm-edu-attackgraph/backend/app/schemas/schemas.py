"""
Pydantic Schemas for LLM-EduAttackGraph API

Organized by domain:
- Target schemas
- Scan schemas
- Fingerprint schemas
- RAG/Retrieval schemas
- Analysis schemas
- Finding/Validation schemas
- Report schemas
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


# ==============================================================================
# Base
# ==============================================================================

class BaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Target Schemas
# ==============================================================================

class TargetCreate(BaseModel):
    hostname: str = Field(..., description="Target hostname or IP address")
    description: Optional[str] = None
    authorization_note: Optional[str] = Field(
        None,
        description="Documentation of authorization (e.g., 'localhost test environment')"
    )


class TargetResponse(BaseResponse):
    id: str
    hostname: str
    ip_address: Optional[str] = None
    description: Optional[str] = None
    authorized: bool
    authorization_note: Optional[str] = None
    created_at: datetime


# ==============================================================================
# Scan Schemas
# ==============================================================================

class ScanCreate(BaseModel):
    target_id: str
    notes: Optional[str] = None


class ScanResponse(BaseResponse):
    id: str
    target_id: str
    status: str
    initiated_by: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    embedding_model: Optional[str] = None
    similarity_threshold: Optional[float] = None
    top_k: Optional[int] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    prompt_version: Optional[str] = None
    error_message: Optional[str] = None


class ScanListResponse(BaseResponse):
    scans: List[ScanResponse]
    total: int


# ==============================================================================
# Port / Service Schemas
# ==============================================================================

class PortInfo(BaseModel):
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    evidence_type: str = "observed"


# ==============================================================================
# Fingerprint Schemas
# ==============================================================================

class FingerprintResponse(BaseResponse):
    """
    Structured fingerprint — output of Stage 1 (Algorithm 1).
    All fields labeled OBSERVED (directly obtained from reconnaissance).
    """
    id: str
    scan_id: str
    target_hostname: str
    web_framework: Optional[str] = None
    web_application: Optional[str] = None
    server_software: Optional[str] = None
    server_version: Optional[str] = None
    technologies: Optional[List[str]] = None
    cms: Optional[str] = None
    text_representation: Optional[str] = None
    evidence_type: str = "observed"
    raw_data: Optional[Dict[str, Any]] = None
    created_at: datetime


# ==============================================================================
# RAG / Retrieval Schemas
# ==============================================================================

class RetrievalResultItem(BaseModel):
    """One item from FAISS retrieval."""
    chunk_id: str
    document_id: str
    source: str                     # awesome-poc, etc.
    title: Optional[str] = None
    technology: Optional[str] = None
    category: Optional[str] = None
    chunk_text: str
    similarity_score: float         # cosine similarity
    evidence_type: str = "retrieved"


class RetrievalResponse(BaseResponse):
    """
    RAG retrieval result.
    Paper: cosine similarity with threshold 0.6.
    """
    id: str
    scan_id: str
    fingerprint_id: str
    query_text: str
    top_k: int
    similarity_threshold: float     # Paper: 0.6
    max_similarity: Optional[float] = None
    threshold_passed: bool
    results: List[RetrievalResultItem]
    created_at: datetime

    # Clear evidence labeling
    note: str = Field(
        default="Results labeled RETRIEVED — from historical knowledge base (Awesome-POC). "
                "These are reference examples, not confirmed vulnerabilities.",
    )


# ==============================================================================
# Analysis Schemas
# ==============================================================================

class AnalysisRequest(BaseModel):
    scan_id: str
    retrieval_id: Optional[str] = None


class AnalysisResponse(BaseResponse):
    """
    LLM analysis result.
    ALL fields labeled INFERRED — not confirmed vulnerabilities.
    Paper: "DeepSeek generates a comprehensive and informed response"
    """
    id: str
    scan_id: str
    llm_provider: str
    llm_model: str
    prompt_version: str

    # LLM-generated content (INFERRED)
    potential_vulnerability: Optional[str] = None
    category: Optional[str] = None
    affected_technology: Optional[str] = None
    evidence_summary: Optional[List[str]] = None
    analysis_text: Optional[str] = None
    severity: Optional[str] = None
    remediation_steps: Optional[List[str]] = None
    uncertainty_statement: Optional[str] = None
    validation_required: bool = True
    evidence_type: str = "inferred"

    created_at: datetime

    # Critical disclaimer
    disclaimer: str = Field(
        default="This analysis is INFERRED by an LLM from historical vulnerability data. "
                "It is NOT a confirmed vulnerability. Human validation is required.",
    )


# ==============================================================================
# Finding Schemas
# ==============================================================================

class FindingResponse(BaseResponse):
    id: str
    scan_id: str
    analysis_id: str
    title: str
    category: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    affected_components: Optional[List[str]] = None
    remediation: Optional[List[str]] = None
    status: str  # POTENTIAL | PENDING_REVIEW | VALIDATED | REJECTED | NEEDS_MORE_EVIDENCE
    evidence_type: str  # inferred | validated
    created_at: datetime
    updated_at: Optional[datetime] = None


# ==============================================================================
# Validation Schemas
# ==============================================================================

class ValidationCreate(BaseModel):
    reviewer: str = Field(..., description="Security analyst identifier")
    comment: Optional[str] = None
    additional_evidence_requested: Optional[str] = None


class ValidationResponse(BaseResponse):
    id: str
    finding_id: str
    reviewer: str
    review_timestamp: datetime
    old_status: str
    new_status: str
    comment: Optional[str] = None


# ==============================================================================
# Report Schemas
# ==============================================================================

class ReportResponse(BaseResponse):
    id: str
    scan_id: str
    title: str
    format: str
    total_findings: int
    validated_findings: int
    rejected_findings: int
    pending_findings: int
    content: str
    created_at: datetime


# ==============================================================================
# Health Check
# ==============================================================================

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.1.0"
    app_env: str
    embedding_model: str
    similarity_threshold: float
    llm_provider: str
    knowledge_base_ready: bool = False
    faiss_index_ready: bool = False
    demo_mode: bool = False


# ==============================================================================
# Error Schemas
# ==============================================================================

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None

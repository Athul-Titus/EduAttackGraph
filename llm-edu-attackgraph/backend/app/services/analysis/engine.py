"""
Analysis Engine — Orchestrates the full Stage 2 pipeline:
    StructuredFingerprint → RAG Retrieval → LLM Inference → Finding Creation

Paper flow (Algorithm 2 online phase):
    1. Embed fingerprint text (same model as offline)
    2. FAISS retrieval → cosine similarity → threshold check (0.6)
    3. If threshold passed: Prompt = Φ(T₂) ⊕ Ψ(T) ⊕ Γ → DeepSeek
    4. Parse structured LLM output → create Finding (status=POTENTIAL)
    5. Return for human validation

All findings start as POTENTIAL (INFERRED) — never auto-confirmed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import uuid

from app.services.embeddings.provider import EmbeddingProvider, get_embedding_provider
from app.services.vector_store.faiss_store import FAISSVectorStore, SearchResult, get_vector_store
from app.services.rag.engine import RAGEngine, RetrievalResult, RAGContext
from app.services.llm.providers import (
    LLMProvider, LLMOutputParser, LLMGuardrails, LLMAnalysisOutput, get_llm_provider
)
from app.services.fingerprinting.engine import StructuredFingerprint
from app.config import settings


# ==============================================================================
# Analysis Result (structured output of full pipeline run)
# ==============================================================================

@dataclass
class PipelineResult:
    """
    Complete result of one full pipeline run:
    Fingerprint → RAG → LLM → Finding
    """
    scan_id: str
    fingerprint: StructuredFingerprint
    retrieval: Optional[RetrievalResult]
    llm_output: Optional[LLMAnalysisOutput]
    prompt_text: Optional[str]
    raw_llm_response: Optional[str]

    # Finding fields
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: Optional[str] = None
    category: str = "UNKNOWN"
    severity: Optional[str] = None
    description: Optional[str] = None
    affected_components: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    uncertainty: Optional[str] = None

    # Always starts as POTENTIAL, always INFERRED
    finding_status: str = "potential"
    evidence_type: str = "inferred"

    # Metadata
    embedding_model: str = ""
    llm_provider: str = ""
    llm_model: str = ""
    prompt_version: str = "v1"
    similarity_threshold: float = 0.60
    max_similarity: Optional[float] = None
    threshold_passed: bool = False
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Error handling
    error: Optional[str] = None
    no_relevant_vulnerabilities: bool = False

    def to_api_dict(self) -> dict:
        """Serialize to API response dict."""
        return {
            "scan_id": self.scan_id,
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "affected_components": self.affected_components,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "uncertainty": self.uncertainty,
            "finding_status": self.finding_status,
            "evidence_type": self.evidence_type,
            "embedding_model": self.embedding_model,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "prompt_version": self.prompt_version,
            "similarity_threshold": self.similarity_threshold,
            "max_similarity": self.max_similarity,
            "threshold_passed": self.threshold_passed,
            "no_relevant_vulnerabilities": self.no_relevant_vulnerabilities,
            "created_at": self.created_at,
            "error": self.error,
            "retrieval_results": [
                {
                    "chunk_id": r.chunk_id,
                    "source": r.source,
                    "title": r.title,
                    "technology": r.technology,
                    "category": r.category,
                    "similarity_score": r.similarity_score,
                    "evidence_type": "retrieved",
                }
                for r in (self.retrieval.results if self.retrieval else [])
            ],
            "disclaimer": (
                "This analysis is INFERRED by an LLM from historical vulnerability data. "
                "It is NOT a confirmed vulnerability. Human validation is required."
            ),
        }


# ==============================================================================
# Analysis Engine
# ==============================================================================

class AnalysisEngine:
    """
    Orchestrates the full Stage 2 pipeline (Algorithm 2 online phase).

    Dependencies:
    - RAGEngine (handles embedding + FAISS retrieval + prompt construction)
    - LLMProvider (sends prompt to DeepSeek/Groq/NVIDIA/OpenAI/Mock)
    - LLMOutputParser (parses structured JSON response)
    - LLMGuardrails (sanitizes inputs/outputs)
    """

    def __init__(
        self,
        rag_engine: Optional[RAGEngine] = None,
        llm_provider: Optional[LLMProvider] = None,
        output_parser: Optional[LLMOutputParser] = None,
        guardrails: Optional[LLMGuardrails] = None,
    ):
        self._rag_engine = rag_engine
        self._llm_provider = llm_provider
        self._output_parser = output_parser or LLMOutputParser()
        self._guardrails = guardrails or LLMGuardrails()

    @property
    def rag_engine(self) -> RAGEngine:
        if self._rag_engine is None:
            self._rag_engine = RAGEngine()
        return self._rag_engine

    @property
    def llm_provider(self) -> LLMProvider:
        if self._llm_provider is None:
            self._llm_provider = get_llm_provider()
        return self._llm_provider

    async def run_pipeline(
        self,
        fingerprint: StructuredFingerprint,
        top_k: Optional[int] = None,
        threshold: Optional[float] = None,
    ) -> PipelineResult:
        """
        Run the complete Stage 2 pipeline.

        Returns PipelineResult with all pipeline outputs for storage and audit.
        """
        result = PipelineResult(
            scan_id=fingerprint.scan_id,
            fingerprint=fingerprint,
            retrieval=None,
            llm_output=None,
            prompt_text=None,
            raw_llm_response=None,
            embedding_model=self.rag_engine.embedding_provider.get_model_name(),
            llm_provider=self.llm_provider.get_provider_name(),
            llm_model=self.llm_provider.get_model_name(),
            similarity_threshold=threshold or settings.SIMILARITY_THRESHOLD,
        )

        try:
            # Step 1: RAG retrieval and context building
            rag_context = await self.rag_engine.build_context(
                fingerprint=fingerprint,
                top_k=top_k,
                threshold=threshold,
            )

            # Also get retrieval for metadata
            query_text = fingerprint.to_text()
            retrieval = await self.rag_engine.retrieve(
                query_text=query_text,
                top_k=top_k,
                threshold=threshold,
            )
            result.retrieval = retrieval
            result.max_similarity = retrieval.max_similarity
            result.threshold_passed = retrieval.threshold_passed

            # Step 2: Check threshold
            if rag_context is None:
                result.no_relevant_vulnerabilities = True
                result.title = "No Relevant Vulnerabilities Detected"
                result.description = (
                    "No historical vulnerability cases exceeded the similarity threshold "
                    f"({result.similarity_threshold}). "
                    "The fingerprint did not match known vulnerability patterns in the knowledge base."
                )
                return result

            # Step 3: Sanitize evidence before including in prompt (guardrails)
            safe_prompt = self._guardrails.sanitize_fingerprint(rag_context.full_prompt)
            result.prompt_text = safe_prompt

            # Step 4: LLM inference
            raw_response = await self.llm_provider.complete(safe_prompt)
            result.raw_llm_response = raw_response

            # Step 5: Parse structured output
            llm_output = self._output_parser.parse(raw_response)
            llm_output = self._guardrails.validate_output(llm_output)
            result.llm_output = llm_output

            # Step 6: Map to finding fields
            result.title = llm_output.potential_vulnerability or "Potential Vulnerability Detected"
            result.category = llm_output.category or "UNKNOWN"
            result.severity = llm_output.severity
            result.description = llm_output.analysis
            result.affected_components = (
                [llm_output.affected_technology] if llm_output.affected_technology else []
            )
            result.remediation = llm_output.remediation or []
            result.evidence = llm_output.evidence or []
            result.uncertainty = llm_output.uncertainty

        except Exception as e:
            result.error = str(e)
            result.title = f"Pipeline Error: {type(e).__name__}"
            result.description = str(e)

        return result


# ==============================================================================
# Validation Service (Human-in-the-loop FSM)
# ==============================================================================

class ValidationService:
    """
    Manages the human-in-the-loop finding validation workflow.

    State machine (paper: human expert reviews LLM output):
        POTENTIAL → PENDING_REVIEW → VALIDATED
                                   → REJECTED
                                   → NEEDS_MORE_EVIDENCE → PENDING_REVIEW
    """

    VALID_TRANSITIONS = {
        "potential": ["pending_review"],
        "pending_review": ["validated", "rejected", "needs_more_evidence"],
        "needs_more_evidence": ["pending_review"],
        "validated": [],      # Terminal state
        "rejected": [],       # Terminal state
    }

    def validate_transition(self, current_status: str, new_status: str) -> None:
        """Check if a status transition is valid."""
        allowed = self.VALID_TRANSITIONS.get(current_status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid status transition: {current_status!r} → {new_status!r}. "
                f"Allowed transitions from {current_status!r}: {allowed}"
            )


# ==============================================================================
# Report Generator
# ==============================================================================

class ReportGenerator:
    """
    Generates structured security reports from scan results.

    Report sections (per paper's described output):
    1. Executive Summary
    2. Target Information
    3. Scan Metadata (embedding model, threshold, LLM provider)
    4. Fingerprint (OBSERVED evidence)
    5. RAG Retrieval (RETRIEVED evidence with similarity scores)
    6. LLM Analysis (INFERRED potential findings)
    7. Human Validation Status
    8. Remediation Recommendations
    9. Limitations and Disclaimers
    10. Evidence Provenance
    """

    def generate_json_report(
        self,
        scan_id: str,
        target: str,
        fingerprint_data: dict,
        pipeline_result: PipelineResult,
        validated_findings: List[dict] = None,
    ) -> dict:
        """Generate structured JSON report."""
        return {
            "report_metadata": {
                "report_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "generated_at": datetime.utcnow().isoformat(),
                "tool": "LLM-EduAttackGraph",
                "tool_version": "0.1.0",
                "paper_reference": "Liu et al., IEEE IoT Journal, Vol.13 No.2, 2026",
            },
            "target": {
                "hostname": target,
                "scan_id": scan_id,
            },
            "methodology": {
                "stage_1": "Website Fingerprinting (Algorithm 1)",
                "stage_2": "LLM-Driven Penetration Path Inference (Algorithm 2)",
                "embedding_model": pipeline_result.embedding_model,
                "similarity_threshold": pipeline_result.similarity_threshold,
                "top_k": settings.TOP_K,
                "llm_provider": pipeline_result.llm_provider,
                "llm_model": pipeline_result.llm_model,
                "knowledge_base": "Awesome-POC (github.com/Threekiii/Awesome-POC)",
            },
            "fingerprint": {
                "evidence_type": "OBSERVED",
                "note": "Directly obtained from reconnaissance",
                "data": fingerprint_data,
            },
            "rag_retrieval": {
                "evidence_type": "RETRIEVED",
                "note": "Historical vulnerability cases from Awesome-POC knowledge base",
                "max_similarity": pipeline_result.max_similarity,
                "threshold": pipeline_result.similarity_threshold,
                "threshold_passed": pipeline_result.threshold_passed,
                "results": [
                    {
                        "source": r.source,
                        "title": r.title,
                        "technology": r.technology,
                        "similarity_score": r.similarity_score,
                        "evidence_type": "RETRIEVED",
                    }
                    for r in (pipeline_result.retrieval.results if pipeline_result.retrieval else [])
                ],
            },
            "potential_findings": [
                {
                    "finding_id": pipeline_result.finding_id,
                    "title": pipeline_result.title,
                    "category": pipeline_result.category,
                    "severity": pipeline_result.severity,
                    "analysis": pipeline_result.description,
                    "affected_components": pipeline_result.affected_components,
                    "remediation": pipeline_result.remediation,
                    "evidence": pipeline_result.evidence,
                    "uncertainty": pipeline_result.uncertainty,
                    "status": pipeline_result.finding_status,
                    "evidence_type": "INFERRED",
                    "note": "LLM-inferred finding. NOT a confirmed vulnerability.",
                }
            ] if not pipeline_result.no_relevant_vulnerabilities else [],
            "validated_findings": validated_findings or [],
            "limitations": [
                "This tool does not detect logical or business-flow vulnerabilities (paper limitation).",
                "LLM outputs are INFERRED — not confirmed findings without human validation.",
                "Performance metrics from the paper (98.89% accuracy) were obtained under specific "
                "conditions and have not been independently reproduced here.",
                "The knowledge base reflects known public vulnerability patterns; novel vulnerabilities "
                "may not be detected.",
            ],
            "disclaimer": (
                "This report is a decision-support tool for authorized security analysts. "
                "All 'potential findings' are INFERRED by an LLM from historical data and require "
                "human validation before being treated as confirmed vulnerabilities. "
                "This tool is not an autonomous exploitation system."
            ),
        }

    def generate_markdown_report(self, json_report: dict) -> str:
        """Convert JSON report to markdown format."""
        md = []
        meta = json_report["report_metadata"]
        target = json_report["target"]
        methodology = json_report["methodology"]
        retrieval = json_report["rag_retrieval"]
        findings = json_report.get("potential_findings", [])

        md.append(f"# Security Analysis Report")
        md.append(f"\n**Generated**: {meta['generated_at']}")
        md.append(f"**Tool**: {meta['tool']} v{meta['tool_version']}")
        md.append(f"**Paper**: {meta['paper_reference']}\n")

        md.append(f"---\n## Target\n**Host**: `{target['hostname']}`\n")

        md.append("## Methodology")
        md.append(f"- Stage 1: {methodology['stage_1']}")
        md.append(f"- Stage 2: {methodology['stage_2']}")
        md.append(f"- Embedding Model: `{methodology['embedding_model']}`")
        md.append(f"- Similarity Threshold: `{methodology['similarity_threshold']}` (paper default)")
        md.append(f"- LLM Provider: `{methodology['llm_provider']}` / `{methodology['llm_model']}`")
        md.append(f"- Knowledge Base: {methodology['knowledge_base']}\n")

        md.append("## RAG Retrieval")
        md.append(f"> **Evidence Type: RETRIEVED** — from historical knowledge base")
        md.append(f"- Max Similarity: `{retrieval['max_similarity']:.4f}`")
        md.append(f"- Threshold Passed: `{retrieval['threshold_passed']}`\n")

        if findings:
            md.append("## Potential Findings")
            md.append("> ⚠️ **INFERRED** — NOT confirmed vulnerabilities. Human validation required.\n")
            for f in findings:
                md.append(f"### {f['title']}")
                md.append(f"- **Category**: {f['category']}")
                md.append(f"- **Severity**: {f['severity']}")
                md.append(f"- **Status**: {f['status'].upper()}")
                md.append(f"- **Evidence Type**: {f['evidence_type']}")
                if f.get("analysis"):
                    md.append(f"\n**Analysis**:\n{f['analysis']}\n")
                if f.get("remediation"):
                    md.append("**Remediation**:")
                    for step in f["remediation"]:
                        md.append(f"  - {step}")
                if f.get("uncertainty"):
                    md.append(f"\n**Uncertainty**: {f['uncertainty']}")
                md.append("")
        else:
            md.append("## Result\nNo relevant vulnerabilities detected above similarity threshold.\n")

        md.append("## Limitations")
        for lim in json_report.get("limitations", []):
            md.append(f"- {lim}")

        md.append(f"\n---\n> {json_report['disclaimer']}")
        return "\n".join(md)

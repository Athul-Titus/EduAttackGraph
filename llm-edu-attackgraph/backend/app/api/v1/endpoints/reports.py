"""
Reports API — Generate and retrieve security reports.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import (
    Scan, Fingerprint, Retrieval, Analysis, Finding, FindingStatus, Report, AuditEvent
)
from app.services.analysis.engine import ReportGenerator
from app.config import settings

router = APIRouter()
report_gen = ReportGenerator()


@router.post("/{scan_id}/generate", status_code=201)
async def generate_report(
    scan_id: str,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a security report for a completed scan.
    Includes: fingerprint (OBSERVED), retrieval (RETRIEVED), findings (INFERRED + VALIDATED).
    """
    # Check scan exists and is complete
    s_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = s_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status.value not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail=f"Scan not complete (status: {scan.status.value})")

    # Get related data
    fp_result = await db.execute(select(Fingerprint).where(Fingerprint.scan_id == scan_id))
    fingerprint = fp_result.scalar_one_or_none()

    ret_result = await db.execute(select(Retrieval).where(Retrieval.scan_id == scan_id))
    retrieval = ret_result.scalar_one_or_none()

    analysis_result = await db.execute(select(Analysis).where(Analysis.scan_id == scan_id))
    analysis = analysis_result.scalar_one_or_none()

    f_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = f_result.scalars().all()

    # Build report data
    from app.services.fingerprinting.engine import StructuredFingerprint
    pipeline_mock = _build_pipeline_result_for_report(scan, fingerprint, retrieval, analysis)

    validated_findings = [
        {"id": f.id, "title": f.title, "status": f.status.value}
        for f in findings if f.status == FindingStatus.VALIDATED
    ]

    target_hostname = fingerprint.target_hostname if fingerprint else scan.target_id
    json_report = report_gen.generate_json_report(
        scan_id=scan_id,
        target=target_hostname,
        fingerprint_data=fingerprint.raw_data if fingerprint else {},
        pipeline_result=pipeline_mock,
        validated_findings=validated_findings,
    )

    # Determine content by format
    if format == "markdown":
        content = report_gen.generate_markdown_report(json_report)
        content_str = content
    else:
        content_str = json.dumps(json_report, indent=2, default=str)

    # Count findings
    total = len(findings)
    validated_count = sum(1 for f in findings if f.status == FindingStatus.VALIDATED)
    rejected_count = sum(1 for f in findings if f.status == FindingStatus.REJECTED)
    pending_count = total - validated_count - rejected_count

    # Persist report
    report = Report(
        scan_id=scan_id,
        title=f"Security Report — {target_hostname} — {datetime.utcnow().strftime('%Y-%m-%d')}",
        format=format,
        content=content_str,
        total_findings=total,
        validated_findings=validated_count,
        rejected_findings=rejected_count,
        pending_findings=pending_count,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    if format == "markdown":
        return PlainTextResponse(content=content_str, media_type="text/markdown")
    return json_report


@router.get("/{scan_id}", response_model=List[dict])
async def list_scan_reports(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc())
    )
    reports = result.scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "format": r.format,
            "total_findings": r.total_findings,
            "validated_findings": r.validated_findings,
            "rejected_findings": r.rejected_findings,
            "pending_findings": r.pending_findings,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


def _build_pipeline_result_for_report(scan, fingerprint, retrieval, analysis):
    """Build a minimal PipelineResult-like object for the report generator."""
    from app.services.analysis.engine import PipelineResult
    from app.services.fingerprinting.engine import StructuredFingerprint
    from app.services.rag.engine import RetrievalResult, SearchResult
    from app.services.llm.providers import LLMAnalysisOutput

    # Build minimal retrieval
    ret_obj = None
    if retrieval:
        results = []
        for r in (retrieval.results or []):
            results.append(SearchResult(
                faiss_index_id=0,
                chunk_id=r.get("chunk_id", ""),
                document_id="",
                source=r.get("source", ""),
                title=r.get("title"),
                technology=r.get("technology"),
                category=r.get("category"),
                chunk_text=r.get("chunk_text", ""),
                similarity_score=r.get("similarity_score", 0.0),
            ))
        from dataclasses import dataclass

        @dataclass
        class SimpleRetrieval:
            results: list
            max_similarity: float
            threshold_passed: bool

        ret_obj = SimpleRetrieval(
            results=results,
            max_similarity=retrieval.max_similarity or 0.0,
            threshold_passed=retrieval.threshold_passed or False,
        )

    fp_struct = None
    if fingerprint:
        fp_struct = StructuredFingerprint(
            target=fingerprint.target_hostname,
            scan_id=scan.id,
            timestamp=fingerprint.created_at.isoformat() if fingerprint.created_at else "",
        )

    result = PipelineResult(
        scan_id=scan.id,
        fingerprint=fp_struct,
        retrieval=ret_obj,
        llm_output=None,
        prompt_text=analysis.prompt_text if analysis else None,
        raw_llm_response=analysis.raw_llm_response if analysis else None,
        title=analysis.potential_vulnerability if analysis else "No Analysis",
        category=analysis.category.value if analysis and analysis.category else "UNKNOWN",
        severity=analysis.severity.value if analysis and analysis.severity else None,
        description=analysis.analysis_text if analysis else None,
        affected_components=[analysis.affected_technology] if analysis and analysis.affected_technology else [],
        remediation=analysis.remediation_steps or [] if analysis else [],
        evidence=analysis.evidence_summary or [] if analysis else [],
        uncertainty=analysis.uncertainty_statement if analysis else None,
        embedding_model=scan.embedding_model or settings.EMBEDDING_MODEL,
        llm_provider=scan.llm_provider or settings.LLM_PROVIDER.value,
        llm_model=scan.llm_model or "",
        similarity_threshold=scan.similarity_threshold or settings.SIMILARITY_THRESHOLD,
        max_similarity=retrieval.max_similarity if retrieval else None,
        threshold_passed=retrieval.threshold_passed if retrieval else False,
        no_relevant_vulnerabilities=not bool(analysis),
    )
    return result

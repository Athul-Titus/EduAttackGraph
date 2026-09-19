"""
Scans API Endpoints — Core pipeline orchestration.

A scan session represents one complete run:
  Target → Fingerprint → RAG → LLM → Finding(s) → Validation → Report
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import (
    Target, Scan, ScanStatus, Port, PortState, Service, Fingerprint,
    Retrieval, Analysis, Finding, FindingStatus, EvidenceType, VulnerabilityCategory,
    AuditEvent
)
from app.schemas.schemas import ScanCreate, ScanResponse, ScanListResponse
from app.services.fingerprinting.engine import FingerprintEngine
from app.services.analysis.engine import AnalysisEngine, PipelineResult
from app.config import settings

router = APIRouter()

# Engine instances (shared across requests)
_fingerprint_engine: Optional[FingerprintEngine] = None
_analysis_engine: Optional[AnalysisEngine] = None


def get_fingerprint_engine() -> FingerprintEngine:
    global _fingerprint_engine
    if _fingerprint_engine is None:
        _fingerprint_engine = FingerprintEngine()
    return _fingerprint_engine


def get_analysis_engine() -> AnalysisEngine:
    global _analysis_engine
    if _analysis_engine is None:
        _analysis_engine = AnalysisEngine()
    return _analysis_engine


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    target_id: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List all scan sessions."""
    query = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    if target_id:
        query = query.where(Scan.target_id == target_id)
    result = await db.execute(query)
    scans = result.scalars().all()

    count_query = select(Scan)
    if target_id:
        count_query = count_query.where(Scan.target_id == target_id)
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    return ScanListResponse(scans=list(scans), total=total)


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Create and start a new scan session.
    The scan runs asynchronously in the background.
    """
    # Verify target exists and is authorized
    t_result = await db.execute(select(Target).where(Target.id == payload.target_id))
    target = t_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.authorized:
        raise HTTPException(status_code=403, detail="Target is not authorized for scanning")

    # Create scan record
    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
        notes=payload.notes,
        embedding_model=settings.EMBEDDING_MODEL,
        similarity_threshold=settings.SIMILARITY_THRESHOLD,
        top_k=settings.TOP_K,
        llm_provider=settings.LLM_PROVIDER.value,
        prompt_version=settings.PROMPT_VERSION,
    )
    db.add(scan)
    db.add(AuditEvent(
        event_type="scan_created",
        entity_type="scan",
        entity_id=scan.id,
        description=f"Scan created for target {target.hostname}",
        data={"target_id": target.id, "hostname": target.hostname},
    ))
    await db.flush()
    await db.refresh(scan)

    # Launch scan pipeline in background
    scan_id = scan.id
    hostname = target.hostname
    background_tasks.add_task(run_scan_pipeline, scan_id, hostname)

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/result")
async def get_scan_result(scan_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get the complete result of a finished scan, including:
    - Fingerprint (OBSERVED)
    - RAG retrieval results (RETRIEVED)
    - LLM analysis (INFERRED)
    - Findings status
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == ScanStatus.RUNNING or scan.status == ScanStatus.PENDING:
        return {"scan_id": scan_id, "status": scan.status.value, "message": "Scan still in progress"}

    # Get fingerprint
    fp_result = await db.execute(select(Fingerprint).where(Fingerprint.scan_id == scan_id))
    fingerprint = fp_result.scalar_one_or_none()

    # Get findings
    f_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = f_result.scalars().all()

    # Get analysis
    a_result = await db.execute(select(Analysis).where(Analysis.scan_id == scan_id))
    analysis = a_result.scalar_one_or_none()

    # Get retrievals
    r_result = await db.execute(select(Retrieval).where(Retrieval.scan_id == scan_id))
    retrieval = r_result.scalar_one_or_none()

    return {
        "scan_id": scan_id,
        "status": scan.status.value,
        "target": scan.target_id,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "fingerprint": {
            "web_framework": fingerprint.web_framework if fingerprint else None,
            "server_software": fingerprint.server_software if fingerprint else None,
            "technologies": fingerprint.technologies if fingerprint else [],
            "text_representation": fingerprint.text_representation if fingerprint else None,
            "evidence_type": "OBSERVED",
        } if fingerprint else None,
        "retrieval": {
            "max_similarity": retrieval.max_similarity if retrieval else None,
            "threshold": retrieval.similarity_threshold if retrieval else None,
            "threshold_passed": retrieval.threshold_passed if retrieval else False,
            "top_k": retrieval.top_k if retrieval else None,
            "results": retrieval.results if retrieval else [],
            "evidence_type": "RETRIEVED",
        } if retrieval else None,
        "analysis": {
            "llm_provider": analysis.llm_provider if analysis else None,
            "llm_model": analysis.llm_model if analysis else None,
            "potential_vulnerability": analysis.potential_vulnerability if analysis else None,
            "category": analysis.category.value if analysis and analysis.category else None,
            "severity": analysis.severity.value if analysis and analysis.severity else None,
            "analysis_text": analysis.analysis_text if analysis else None,
            "remediation_steps": analysis.remediation_steps if analysis else [],
            "uncertainty_statement": analysis.uncertainty_statement if analysis else None,
            "evidence_type": "INFERRED",
            "validation_required": True,
        } if analysis else None,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category.value if f.category else None,
                "severity": f.severity.value if f.severity else None,
                "status": f.status.value,
                "evidence_type": f.evidence_type.value if f.evidence_type else "inferred",
            }
            for f in findings
        ],
        "error": scan.error_message,
    }


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        raise HTTPException(status_code=400, detail="Cannot cancel a completed scan")
    scan.status = ScanStatus.CANCELLED


# ==============================================================================
# Background scan pipeline runner
# ==============================================================================

async def run_scan_pipeline(scan_id: str, hostname: str) -> None:
    """
    Background task: runs the full two-stage pipeline.

    Stage 1: Fingerprinting (Algorithm 1)
    Stage 2: RAG + LLM analysis (Algorithm 2)
    """
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            # Get scan
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()

            # Update status
            scan.status = ScanStatus.FINGERPRINTING
            scan.started_at = datetime.utcnow()
            await db.flush()

            # --- STAGE 1: FINGERPRINTING ---
            engine = get_fingerprint_engine()

            # Use demo mode if configured
            if settings.is_demo_mode:
                import json, os
                demo_path = settings.DEMO_FINGERPRINT_PATH
                if os.path.exists(demo_path):
                    with open(demo_path, "r") as f:
                        demo_data = json.load(f)
                    fp_struct = _demo_fingerprint(hostname, scan_id, demo_data)
                else:
                    fp_struct = await engine.scan_target(hostname, scan_id)
            else:
                fp_struct = await engine.scan_target(hostname, scan_id)

            # Save fingerprint to DB
            fingerprint_rec = Fingerprint(
                scan_id=scan_id,
                target_hostname=hostname,
                raw_data=fp_struct.to_dict(),
                web_framework=fp_struct.web_framework,
                web_application=fp_struct.web_application,
                server_software=fp_struct.server_software,
                server_version=fp_struct.server_version,
                technologies=fp_struct.technologies,
                cms=fp_struct.cms,
                text_representation=fp_struct.to_text(),
                evidence_type=EvidenceType.OBSERVED,
            )
            db.add(fingerprint_rec)

            # Save port records
            for pr in fp_struct.port_records:
                port_rec = Port(
                    scan_id=scan_id,
                    port_number=pr.port,
                    state=PortState.OPEN,
                    evidence_type=EvidenceType.OBSERVED,
                )
                db.add(port_rec)
                await db.flush()
                if pr.service:
                    svc_rec = Service(
                        port_id=port_rec.id,
                        name=pr.service.name,
                        version=pr.service.version,
                        product=pr.service.product,
                        banner=pr.service.banner,
                        evidence=pr.service.evidence,
                        evidence_type=EvidenceType.OBSERVED,
                    )
                    db.add(svc_rec)

            await db.flush()
            await db.refresh(fingerprint_rec)

            # --- STAGE 2: RAG + LLM ---
            scan.status = ScanStatus.ANALYZING
            await db.flush()

            analysis_eng = get_analysis_engine()
            pipeline_result = await analysis_eng.run_pipeline(fp_struct)

            # Save retrieval record
            if pipeline_result.retrieval:
                ret = pipeline_result.retrieval
                retrieval_rec = Retrieval(
                    scan_id=scan_id,
                    fingerprint_id=fingerprint_rec.id,
                    query_text=ret.query_text,
                    query_embedding_model=ret.embedding_model,
                    faiss_index_version=settings.FAISS_INDEX_PATH,
                    top_k=ret.top_k,
                    similarity_threshold=ret.similarity_threshold,
                    results=[
                        {
                            "chunk_id": r.chunk_id,
                            "source": r.source,
                            "title": r.title,
                            "technology": r.technology,
                            "category": r.category,
                            "similarity_score": r.similarity_score,
                            "chunk_text": r.chunk_text[:500],
                            "evidence_type": "retrieved",
                        }
                        for r in ret.results
                    ],
                    max_similarity=ret.max_similarity,
                    threshold_passed=ret.threshold_passed,
                )
                db.add(retrieval_rec)
                await db.flush()

            # Save analysis record
            if pipeline_result.llm_output and not pipeline_result.no_relevant_vulnerabilities:
                lo = pipeline_result.llm_output
                severity_map = {
                    "critical": "critical", "high": "high", "medium": "medium",
                    "low": "low", "informational": "informational",
                }
                from app.models.models import SeverityLevel
                severity_val = None
                if lo.severity and lo.severity in severity_map:
                    severity_val = SeverityLevel(lo.severity)

                cat_map = {v.value: v for v in VulnerabilityCategory}
                cat_val = cat_map.get(lo.category, VulnerabilityCategory.UNKNOWN)

                analysis_rec = Analysis(
                    scan_id=scan_id,
                    retrieval_id=retrieval_rec.id if pipeline_result.retrieval else None,
                    llm_provider=pipeline_result.llm_provider,
                    llm_model=pipeline_result.llm_model,
                    prompt_version=pipeline_result.prompt_version,
                    prompt_text=pipeline_result.prompt_text or "",
                    raw_llm_response=pipeline_result.raw_llm_response or "",
                    potential_vulnerability=lo.potential_vulnerability,
                    category=cat_val,
                    affected_technology=lo.affected_technology,
                    evidence_summary=lo.evidence,
                    analysis_text=lo.analysis,
                    severity=severity_val,
                    remediation_steps=lo.remediation,
                    uncertainty_statement=lo.uncertainty,
                    validation_required=True,
                    evidence_type=EvidenceType.INFERRED,
                )
                db.add(analysis_rec)
                await db.flush()

                # Create Finding (always starts POTENTIAL)
                finding_rec = Finding(
                    scan_id=scan_id,
                    analysis_id=analysis_rec.id,
                    title=pipeline_result.title or "Potential Vulnerability",
                    category=cat_val,
                    severity=severity_val,
                    description=pipeline_result.description,
                    affected_components=pipeline_result.affected_components,
                    remediation=pipeline_result.remediation,
                    status=FindingStatus.POTENTIAL,
                    evidence_type=EvidenceType.INFERRED,
                )
                db.add(finding_rec)

            # Update scan status
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.llm_model = pipeline_result.llm_model

            db.add(AuditEvent(
                event_type="scan_completed",
                entity_type="scan",
                entity_id=scan_id,
                description=f"Scan completed. Threshold passed: {pipeline_result.threshold_passed}",
                data={"max_similarity": pipeline_result.max_similarity},
            ))
            await db.commit()

        except Exception as e:
            async with AsyncSessionLocal() as err_db:
                err_result = await err_db.execute(select(Scan).where(Scan.id == scan_id))
                err_scan = err_result.scalar_one_or_none()
                if err_scan:
                    err_scan.status = ScanStatus.FAILED
                    err_scan.error_message = str(e)[:1000]
                    err_scan.completed_at = datetime.utcnow()
                    await err_db.commit()


def _demo_fingerprint(hostname: str, scan_id: str, demo_data: dict):
    """Build a StructuredFingerprint from demo JSON data."""
    from app.services.fingerprinting.engine import (
        StructuredFingerprint, PortRecord, ServiceInfo, WebFingerprint
    )
    port_records = []
    for pr_data in demo_data.get("port_records", []):
        svc_data = pr_data.get("service", {})
        svc = ServiceInfo(
            port=svc_data.get("port", pr_data["port"]),
            name=svc_data.get("name", "http"),
            version=svc_data.get("version"),
            product=svc_data.get("product"),
            banner=svc_data.get("banner"),
            evidence=svc_data.get("evidence", {}),
        ) if svc_data else None

        fp_data = pr_data.get("fingerprint", {})
        fp = WebFingerprint(
            url=fp_data.get("url", ""),
            framework=fp_data.get("framework"),
            cms=fp_data.get("cms"),
            server=fp_data.get("server"),
            server_version=fp_data.get("server_version"),
            technologies=fp_data.get("technologies", []),
            headers=fp_data.get("headers", {}),
            evidence=fp_data.get("evidence", []),
            status_code=fp_data.get("status_code"),
        ) if fp_data else None

        port_records.append(PortRecord(
            port=pr_data["port"],
            service=svc,
            url=pr_data.get("url"),
            fingerprint=fp,
        ))

    return StructuredFingerprint(
        target=hostname,
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        port_records=port_records,
        web_framework=demo_data.get("web_framework"),
        web_application=demo_data.get("web_application"),
        server_software=demo_data.get("server_software"),
        server_version=demo_data.get("server_version"),
        technologies=demo_data.get("technologies", []),
        cms=demo_data.get("cms"),
    )

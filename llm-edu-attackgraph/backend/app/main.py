"""
LLM-EduAttackGraph — FastAPI Application

Two-stage security analysis system:
Stage 1: Website Fingerprinting (Algorithm 1)
Stage 2: LLM-Driven Penetration Path Inference (Algorithm 2)

Research paper: Liu et al., IEEE Internet of Things Journal, 2026
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    log.info(
        "Starting LLM-EduAttackGraph",
        env=settings.APP_ENV.value,
        llm_provider=settings.LLM_PROVIDER.value,
        embedding_model=settings.EMBEDDING_MODEL,
        similarity_threshold=settings.SIMILARITY_THRESHOLD,
        demo_mode=settings.is_demo_mode,
    )

    # Create database tables and seed admin
    try:
        from app.db.session import create_tables, AsyncSessionLocal
        from app.core.auth import auto_seed_admin
        await create_tables()
        log.info("Database tables initialized")
        async with AsyncSessionLocal() as session:
            await auto_seed_admin(session)
            log.info("Admin account verified (titusathul8@gmail.com)")
    except Exception as e:
        log.warning("Database initialization failed", error=str(e))

    # Try to load FAISS index
    try:
        from app.services.vector_store.faiss_store import get_vector_store
        vs = get_vector_store()
        if vs.is_loaded:
            log.info("FAISS index loaded", num_vectors=vs.num_vectors)
        else:
            log.warning(
                "FAISS index not found. Run 'python scripts/build_faiss_index.py' to build it."
            )
    except Exception as e:
        log.warning("FAISS index load failed", error=str(e))

    if settings.is_demo_mode:
        log.warning(
            "DEMO MODE ACTIVE — Using synthetic data. Not for real security analysis.",
        )

    # Resume any scans that were PENDING or RUNNING when the server last stopped.
    # FastAPI BackgroundTasks are in-memory only — a server restart orphans them.
    try:
        from app.db.session import AsyncSessionLocal
        from app.models.models import Scan, ScanStatus, Target
        from sqlalchemy import select, or_
        import asyncio

        async with AsyncSessionLocal() as recovery_db:
            orphaned_q = await recovery_db.execute(
                select(Scan).where(
                    or_(
                        Scan.status == ScanStatus.PENDING,
                        Scan.status == ScanStatus.RUNNING,
                        Scan.status == ScanStatus.FINGERPRINTING,
                        Scan.status == ScanStatus.ANALYZING,
                    )
                )
            )
            orphaned_scans = orphaned_q.scalars().all()

            if orphaned_scans:
                log.warning(
                    "Recovering orphaned scans from previous session",
                    count=len(orphaned_scans),
                )
                for orphan in orphaned_scans:
                    # Look up hostname
                    t_q = await recovery_db.execute(
                        select(Target).where(Target.id == orphan.target_id)
                    )
                    t = t_q.scalar_one_or_none()
                    hostname = t.hostname if t else "unknown"

                    # Reset to PENDING so the pipeline starts clean
                    orphan.status = ScanStatus.PENDING
                    orphan.started_at = None
                    orphan.error_message = None
                    log.info(
                        "Requeueing orphaned scan",
                        scan_id=orphan.id,
                        hostname=hostname,
                    )
                    # Schedule as asyncio background task
                    from app.api.v1.endpoints.scans import run_scan_pipeline
                    asyncio.create_task(run_scan_pipeline(orphan.id, hostname))

                await recovery_db.commit()
    except Exception as e:
        log.warning("Orphaned scan recovery failed", error=str(e))

    yield

    log.info("Shutting down LLM-EduAttackGraph")



# Create FastAPI app
app = FastAPI(
    title="LLM-EduAttackGraph",
    description=(
        "Human-in-the-loop security vulnerability analysis platform for educational web applications. "
        "Implements the methodology from Liu et al., IEEE Internet of Things Journal, 2026."
    ),
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# Middleware: Request timing
# ==============================================================================

@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    response.headers["X-Process-Time"] = f"{duration:.3f}s"
    return response


# ==============================================================================
# Health Check
# ==============================================================================

@app.get("/api/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """
    System health check.
    Returns status of all subsystems.
    """
    from app.services.vector_store.faiss_store import get_vector_store

    vs = get_vector_store()

    return {
        "status": "healthy",
        "version": "0.1.0",
        "app_env": settings.APP_ENV.value,
        "embedding_model": settings.EMBEDDING_MODEL,
        "similarity_threshold": settings.SIMILARITY_THRESHOLD,
        "top_k": settings.TOP_K,
        "llm_provider": settings.LLM_PROVIDER.value,
        "knowledge_base_ready": vs.is_loaded,
        "faiss_index_ready": vs.is_loaded,
        "faiss_num_vectors": vs.num_vectors if vs.is_loaded else 0,
        "demo_mode": settings.is_demo_mode,
        "authorized_target_mode": settings.AUTHORIZED_TARGET_MODE.value,
        "paper_reference": "Liu et al., LLM-EduAttackGraph, IEEE IoT Journal, 2026",
    }


@app.get("/api/config", tags=["System"])
async def get_config() -> Dict[str, Any]:
    """Return current (non-sensitive) configuration."""
    return {
        "embedding_model": settings.EMBEDDING_MODEL,
        "similarity_threshold": settings.SIMILARITY_THRESHOLD,
        "top_k": settings.TOP_K,
        "llm_provider": settings.LLM_PROVIDER.value,
        "authorized_target_mode": settings.AUTHORIZED_TARGET_MODE.value,
        "allowed_targets": settings.allowed_targets,
        "chunk_size": settings.CHUNK_SIZE,
        "chunk_overlap": settings.CHUNK_OVERLAP,
        "port_scan_range": settings.PORT_SCAN_RANGE,
        "demo_mode": settings.is_demo_mode,
    }


# ==============================================================================
# Include API Routers
# ==============================================================================

try:
    from app.api.v1.endpoints import targets, scans, fingerprints, rag, analysis, findings, reports, demo, auth
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
    app.include_router(targets.router, prefix="/api/v1/targets", tags=["Targets"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(fingerprints.router, prefix="/api/v1/fingerprints", tags=["Fingerprints"])
    app.include_router(rag.router, prefix="/api/v1/rag", tags=["RAG"])
    app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["Analysis"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(demo.router, prefix="/api/v1/demo", tags=["Demo"])
except ImportError as e:
    log.warning("Some API routers not yet implemented", error=str(e))


# ==============================================================================
# Global Exception Handler
# ==============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.APP_ENV.value != "production" else "An error occurred",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.APP_ENV.value == "development",
    )

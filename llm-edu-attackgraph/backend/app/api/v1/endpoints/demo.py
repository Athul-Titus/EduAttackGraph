"""
Demo API Endpoint — Safe exploration without real scanning.

Returns synthetic data clearly labeled as DEMO.
Uses pre-built demo fingerprint + mock LLM responses.
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from fastapi import APIRouter

from app.config import settings
from app.services.fingerprinting.engine import StructuredFingerprint
from app.services.analysis.engine import AnalysisEngine, ReportGenerator
from app.services.embeddings.provider import MockEmbeddingProvider
from app.services.vector_store.faiss_store import FAISSVectorStore
from app.services.rag.engine import RAGEngine
from app.services.llm.providers import MockLLMProvider

router = APIRouter()


@router.get("/")
async def demo_info():
    """Demo mode information."""
    return {
        "demo_mode": True,
        "warning": "All data in this demo is SYNTHETIC — not real security analysis",
        "description": "LLM-EduAttackGraph demo using pre-built RuoYi fingerprint sample",
        "paper_reference": "Liu et al., LLM-EduAttackGraph, IEEE IoT Journal, 2026",
        "endpoints": {
            "run_demo": "/api/v1/demo/run",
            "demo_fingerprint": "/api/v1/demo/fingerprint",
            "demo_knowledge_base": "/api/v1/demo/knowledge-base",
        },
    }


@router.get("/fingerprint")
async def demo_fingerprint():
    """Return the demo fingerprint (RuoYi sample from paper)."""
    demo_path = settings.DEMO_FINGERPRINT_PATH
    if os.path.exists(demo_path):
        with open(demo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["_warning"] = "DEMO DATA — SYNTHETIC — NOT real observed data"
        return data
    return {
        "error": "Demo fingerprint not found",
        "hint": f"Expected at: {demo_path}",
    }


@router.get("/knowledge-base")
async def demo_knowledge_base():
    """Return demo knowledge base samples."""
    demo_kb_path = settings.DEMO_KB_PATH
    if os.path.exists(demo_kb_path):
        with open(demo_kb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {"warning": "DEMO DATA — SYNTHETIC", "documents": data}
    return {"error": "Demo knowledge base not found", "hint": f"Expected at: {demo_kb_path}"}


@router.post("/run")
async def run_demo():
    """
    Run a complete demo pipeline:
    1. Load demo fingerprint (RuoYi)
    2. Mock embedding + mock FAISS retrieval (from demo KB)
    3. Mock LLM analysis
    4. Return complete labeled result

    ALL outputs are clearly labeled DEMO / SYNTHETIC.
    """
    demo_path = settings.DEMO_FINGERPRINT_PATH
    demo_kb_path = settings.DEMO_KB_PATH

    if not os.path.exists(demo_path):
        return {"error": "Demo data not found. Check DEMO_FINGERPRINT_PATH configuration."}

    with open(demo_path, "r", encoding="utf-8") as f:
        demo_data = json.load(f)

    demo_kb = []
    if os.path.exists(demo_kb_path):
        with open(demo_kb_path, "r", encoding="utf-8") as f:
            demo_kb = json.load(f)

    # Build StructuredFingerprint from demo data
    from app.api.v1.endpoints.scans import _demo_fingerprint
    fp = _demo_fingerprint("localhost:8080", "demo-scan-001", demo_data)

    fingerprint_text = fp.to_text()

    # Mock similarity retrieval
    top_result = demo_kb[0] if demo_kb else {}
    similarity_score = top_result.get("similarity_score_demo", 0.87)
    threshold = settings.SIMILARITY_THRESHOLD
    threshold_passed = similarity_score >= threshold

    # Mock LLM
    mock_llm = MockLLMProvider()
    mock_prompt = f"DEMO PROMPT:\n{fingerprint_text}\n\nREFERENCE:\n{top_result.get('description', '')[:500]}"
    raw_response = await mock_llm.complete(mock_prompt)

    try:
        llm_output = json.loads(raw_response)
    except Exception:
        llm_output = {"error": "Could not parse LLM output", "raw": raw_response}

    return {
        "_demo_mode": True,
        "_warning": "ALL DATA IS SYNTHETIC DEMO — NOT REAL SECURITY ANALYSIS",
        "pipeline_stages": {
            "stage_1_fingerprinting": {
                "status": "complete",
                "evidence_type": "DEMO (synthetic OBSERVED)",
                "result": {
                    "target": fp.target,
                    "web_framework": fp.web_framework,
                    "server_software": fp.server_software,
                    "technologies": fp.technologies,
                    "fingerprint_text": fingerprint_text,
                },
            },
            "stage_2_rag": {
                "status": "complete",
                "evidence_type": "DEMO (synthetic RETRIEVED)",
                "embedding_model": f"DEMO/{settings.EMBEDDING_MODEL}",
                "similarity_threshold": threshold,
                "top_result": {
                    "title": top_result.get("title"),
                    "technology": top_result.get("technology"),
                    "category": top_result.get("category"),
                    "similarity_score": similarity_score,
                    "threshold_passed": threshold_passed,
                    "evidence_type": "RETRIEVED",
                },
            },
            "stage_2_llm": {
                "status": "complete",
                "evidence_type": "DEMO (synthetic INFERRED)",
                "llm_provider": "mock",
                "llm_model": "mock-llm-v1",
                "result": llm_output,
                "validation_required": True,
            },
        },
        "finding": {
            "status": "POTENTIAL",
            "evidence_type": "INFERRED",
            "note": "Human validation required. This is DEMO data — not real.",
            "disclaimer": (
                "This is a synthetic demonstration. "
                "No real scanning was performed. "
                "Never treat INFERRED findings as confirmed vulnerabilities."
            ),
        },
    }


@router.get("/vulnerability-categories")
async def vulnerability_categories():
    """Return the six vulnerability categories from the paper."""
    return {
        "source": "Liu et al., LLM-EduAttackGraph, IEEE IoT Journal, 2026",
        "description": "Six vulnerability categories identified in Chinese educational websites",
        "total_vulnerabilities_in_paper": 961,
        "categories": [
            {"code": "O1_RCE", "name": "Remote Code Execution", "paper_prevalence": "3.85%", "count": 37},
            {"code": "O2_SQL_INJECTION", "name": "SQL Injection", "paper_prevalence": "4.05%", "count": 39},
            {"code": "O3_WEAK_PASSWORD", "name": "Weak Password", "paper_prevalence": "55.61%", "count": 535},
            {"code": "O4_UNAUTHORIZED", "name": "Unauthorized Access", "paper_prevalence": "28.20%", "count": 271},
            {"code": "O5_TOKEN_TAMPERING", "name": "Token Tampering", "paper_prevalence": "0.73%", "count": 7},
            {"code": "O6_INFO_DISCLOSURE", "name": "Sensitive Information Disclosure", "paper_prevalence": "5.93%", "count": 57},
        ],
    }

"""
API Endpoints: Targets, Scans, Fingerprints, RAG, Analysis, Findings, Reports, Demo
"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_targets():
    return {"message": "targets endpoint"}

from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def findings_root():
    return {"endpoint": "findings"}

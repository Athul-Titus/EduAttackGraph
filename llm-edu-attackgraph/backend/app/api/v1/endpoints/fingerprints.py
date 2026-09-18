from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def fingerprints_root():
    return {"endpoint": "fingerprints"}

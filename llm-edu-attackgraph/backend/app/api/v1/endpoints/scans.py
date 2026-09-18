from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def scans_root():
    return {"endpoint": "scans"}

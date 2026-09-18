from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def demo_root():
    return {"endpoint": "demo"}

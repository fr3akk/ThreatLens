from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def root():
    return {
        "message": "Welcome to ThreatLens 🚀"
    }


@router.get("/health")
def health():
    return {
        "status": "healthy"
    }
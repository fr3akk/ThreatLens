from fastapi import APIRouter

from backend.ioc.detector import detect_ioc_type
from backend.schemas.ioc import IOCRequest, IOCResponse

router = APIRouter(prefix="/ioc", tags=["IOC"])


@router.post("/detect", response_model=IOCResponse)
def detect_ioc(request: IOCRequest):
    """
    Detect the IOC type.
    """

    ioc_type = detect_ioc_type(request.ioc)

    if ioc_type is None:
        return IOCResponse(
            valid=False,
            error="Unsupported IOC format"
        )

    return IOCResponse(
        valid=True,
        type=ioc_type,
        value=request.ioc.strip()
    )
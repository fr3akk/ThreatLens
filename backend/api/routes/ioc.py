from fastapi import APIRouter
from fastapi import HTTPException

from backend.ioc.detector import detect_ioc_type
from backend.schemas.ioc import IOCRequest, IOCResponse
from backend.api.schemas.enrichment import EnrichmentResponse
from backend.services.ioc_enrichment import IOCEnrichmentService

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


@router.post("/enrich", response_model=EnrichmentResponse)
def enrich_ioc(request: IOCRequest):
    """
    Enrich an IOC using the configured threat intelligence providers.
    """

    service = IOCEnrichmentService()

    try:
        return service.enrich(request.ioc)
    except NotImplementedError as exc:
        raise HTTPException(
            status_code=501,
            detail=str(exc),
        )
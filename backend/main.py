from fastapi import FastAPI

from backend.api.routes.ioc import router as ioc_router

from backend.core.config import settings
from backend.api.routes.health import router as health_router

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
)

app.include_router(health_router)
app.include_router(ioc_router)
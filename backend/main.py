from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from backend.config import settings
from backend.connectors.engine import engine
from backend.services.storage.db import db

# Import routers
from backend.api.sources import router as sources_router
from backend.api.ingestion import router as ingestion_router
from backend.api.parsers import router as parsers_router
from backend.api.events import router as events_router
from backend.api.integrity import router as integrity_router
from backend.api.correlation import router as correlation_router
from backend.api.analytics import router as analytics_router
from backend.api.export import router as export_router
from backend.api.connectors import router as connectors_router
from backend.api.audit import router as audit_router
from backend.api.formats import router as formats_router
from backend.api.receivers import router as receivers_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Start syslog/file/Kafka inputs and output connectors from config/tracelog.yaml
    # (or the file named by TRACELOG_CONFIG). HTTP receivers are always mounted.
    await engine.start()
    yield
    await engine.stop()


app = FastAPI(
    lifespan=lifespan,
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="TRACELOG: receives perimeter device logs, archives each line, normalises it to OCSF 1.1.0, hash-chains it and forwards it to SIEM and observability tools (SIH 2026, PS 26156).",
    # FastAPI's own /docs page loads Swagger UI from a CDN and is blank on an air-gapped network
    # (PS item j). The same files ship in backend/static/swagger-ui and /docs below serves them.
    # ReDoc would need a second CDN bundle and is not offered.
    docs_url=None,
    redoc_url=None,
)

SWAGGER_UI = Path(__file__).parent / "static" / "swagger-ui"
app.mount("/static/swagger-ui", StaticFiles(directory=SWAGGER_UI), name="swagger-ui")


@app.get("/docs", include_in_schema=False)
def swagger_ui():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{settings.PROJECT_NAME} API",
        swagger_js_url="/static/swagger-ui/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui/swagger-ui.css",
        swagger_favicon_url="/static/swagger-ui/favicon-32x32.png",
        # Swagger UI would otherwise ask validator.swagger.io to check the spec
        swagger_ui_parameters={"validatorUrl": None},
    )

# Enable CORS for Streamlit frontend and local tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api prefix
app.include_router(sources_router, prefix=settings.API_PREFIX)
app.include_router(ingestion_router, prefix=settings.API_PREFIX)
app.include_router(parsers_router, prefix=settings.API_PREFIX)
app.include_router(events_router, prefix=settings.API_PREFIX)
app.include_router(integrity_router, prefix=settings.API_PREFIX)
app.include_router(correlation_router, prefix=settings.API_PREFIX)
app.include_router(analytics_router, prefix=settings.API_PREFIX)
app.include_router(export_router, prefix=settings.API_PREFIX)
app.include_router(connectors_router, prefix=settings.API_PREFIX)
app.include_router(audit_router, prefix=settings.API_PREFIX)
app.include_router(formats_router, prefix=settings.API_PREFIX)
app.include_router(receivers_router)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "TRACELOG API",
        "version": settings.VERSION,
        "database": "SQLite (WAL mode)",
        "db_path": str(settings.DB_PATH),
        "environment": settings.ENVIRONMENT
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
